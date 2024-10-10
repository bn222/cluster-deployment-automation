import abc
import contextlib
import dataclasses
import functools
import json
import logging
import os
import re
import sys
import threading
import time
import typing

from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import fields
from dataclasses import is_dataclass
from enum import Enum
from typing import Any
from typing import Literal
from typing import Optional
from typing import TypeVar
from typing import Union
from typing import cast

if typing.TYPE_CHECKING:
    # https://github.com/python/typeshed/tree/main/stdlib/_typeshed#api-stability
    # https://github.com/python/typeshed/blob/6220c20d9360b12e2287511587825217eec3e5b5/stdlib/_typeshed/__init__.pyi#L349
    from _typeshed import DataclassInstance
    from types import TracebackType
    import argparse


common_lock = threading.Lock()

logger = logging.getLogger(__name__)


PathType = Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]

E = TypeVar("E", bound=Enum)
T = TypeVar("T")
TOptionalStr = TypeVar("TOptionalStr", bound=Optional[str])
TOptionalInt = TypeVar("TOptionalInt", bound=Optional[int])
TOptionalBool = TypeVar("TOptionalBool", bound=Optional[bool])
TOptionalFloat = TypeVar("TOptionalFloat", bound=Optional[float])
T1 = TypeVar("T1")
T2 = TypeVar("T2")
TCallable = typing.TypeVar("TCallable", bound=typing.Callable[..., typing.Any])
TStructParseBaseNamed = typing.TypeVar(
    "TStructParseBaseNamed", bound="StructParseBaseNamed"
)


# This is used as default value for some arguments, to recognize that the
# caller didn't specify the argument. This is useful, when we want to
# explicitly distinguish between having an argument unset or set to any value.
# The caller would never pass this value, but the implementation would check
# whether the argument is still left at the default.
#
# See also, dataclasses.MISSING and dataclasses._MISSING_TYPE
class _MISSING_TYPE:
    pass


MISSING = _MISSING_TYPE()

# kw_only is Python3.10+. This annotation is very useful, so make it available
# with 3.9 without breaking mypy.
#
# This silences up mypy while retaining the error checking at runtime. It however
# looses the ability for mypy to detect the error at lint time.
#
# So, using this acts as a comment to the reader that the code expects kw_only.
# It is also enforced at runtime. It also allows to find all the places where
# we would like to use kw_only=True but cannot due to Python 3.9 compatibility.
KW_ONLY_DATACLASS = {"kw_only": True} if "kw_only" in dataclass.__kwdefaults__ else {}


def bool_to_str(val: bool, *, format: str = "true") -> str:
    if format == "true":
        return "true" if val else "false"
    if format == "yes":
        return "yes" if val else "no"
    raise ValueError(f'Invalid format "{format}"')


def str_to_bool(
    val: Optional[Union[str, bool]],
    on_error: Union[T1, _MISSING_TYPE] = MISSING,
    *,
    on_default: Union[T2, _MISSING_TYPE] = MISSING,
) -> Union[bool, T1, T2]:

    is_default = False

    if isinstance(val, str):
        val2 = val.lower().strip()
        if val2 in ("1", "y", "yes", "true", "on"):
            return True
        if val2 in ("0", "n", "no", "false", "off"):
            return False
        if val2 in ("", "default", "-1"):
            is_default = True
    elif val is None:
        # None is (maybe) accepted as default value.
        is_default = True
    elif isinstance(val, bool):
        # For convenience, also accept that the value is already a boolean.
        return val

    if is_default and not isinstance(on_default, _MISSING_TYPE):
        # The value is explicitly set to one of the recognized default values
        # (None, "default", "-1" or "").
        #
        # By setting @on_default, the caller can use str_to_bool() to not only
        # parse boolean values, but ternary values.
        return on_default

    if not isinstance(on_error, _MISSING_TYPE):
        # On failure, we return the fallback value.
        return on_error

    raise ValueError(f"Value {val} is not a boolean")


@typing.overload
def iter_get_first(
    lst: Iterable[T],
    *,
    unique: typing.Literal[True],
    force_unique: typing.Literal[True],
    single: bool = False,
) -> T:
    pass


@typing.overload
def iter_get_first(
    lst: Iterable[T],
    *,
    unique: bool = False,
    force_unique: bool = False,
    single: typing.Literal[True],
) -> T:
    pass


@typing.overload
def iter_get_first(
    lst: Iterable[T],
    *,
    unique: bool = False,
    force_unique: bool = False,
    single: bool = False,
) -> Optional[T]:
    pass


def iter_get_first(
    lst: Iterable[T],
    *,
    unique: bool = False,
    force_unique: bool = False,
    single: bool = False,
) -> Optional[T]:
    """
    Returns the first item from the iterable `lst` based on specified conditions.

    The function behaves differently depending on the parameters:

    - By default, if neither `unique`, `force_unique` or `single` is set, the
      function simply returns the first item from the iterable, or `None` if the
      iterable is empty.

    - If `unique=True`, it returns the first item if the iterable only contains
      a single element. Otherwise `None` is returned.

    - If `force_unique=True`, it ensures the iterable contains at most one
      item and raises a ValueError if multiple unique items are found. An
      empty iterable will give `None`.

    - Setting both `unique=True` and `force_unique=True` together or setting
      `single=True` enforces that the iterable contains exactly one element and
      returns it (raising an ValueError otherwise).

    Args:
        lst (Iterable[T]): The input iterable.
        unique (bool, optional): Returns `None` if the iterable contains multiple elements. Defaults to False.
        force_unique (bool, optional): Raises a ValueError if the iterable contains multiple elements. Defaults to False.
        single (bool, optional): Shorthand for `unique=True` and `force_unique=True` to raise a ValueError if the iterable does not contain exaclty one element. Defaults to False.

    Returns:
        Optional[T]: The first item from the iterable, or `None` if the iterable is empty. Raises an error if conditions set
        by `unique`, `force_unique`, or `single` are violated.
    """
    if single:
        # This is a shorthand for setting both "unique" and "force_unique".
        unique = True
        force_unique = True
    itr = iter(lst)
    try:
        v0 = next(itr)
    except StopIteration:
        if unique and force_unique:
            # Usually, an empty iterable is accepted, unless "unique" and
            # "force_unique" are both True.
            raise ValueError(
                "Iterable was expected to contain one element but was empty"
            )
        return None
    try:
        next(itr)
    except StopIteration:
        # There is only one element, we are good.
        pass
    else:
        # Handle multiple elements.
        if force_unique:
            raise ValueError("Iterable was expected to only contain one entry")
        if unique:
            return None
    return v0


def iter_filter_none(lst: Iterable[Optional[T]]) -> Iterable[T]:
    for v in lst:
        if v is not None:
            yield v


def unwrap(val: Optional[T], *, or_else: Optional[T] = None) -> T:
    # Like Rust's unwrap. Get the value or die (with an exception).
    #
    # The error message here is not good, so this function is more for
    # asserting (and shutting up the type checker) in cases where we
    # expect to have a value.
    if val is None:
        if or_else is not None:
            return or_else
        raise ValueError("Optional value unexpectedly not set")
    return val


def enum_convert(
    enum_type: type[E],
    value: Any,
    default: Optional[E] = None,
) -> E:

    if value is None:
        # We only allow None, if the caller also specified a default value.
        if default is not None:
            return default
    elif isinstance(value, enum_type):
        return value
    elif isinstance(value, int):
        try:
            return enum_type(value)
        except ValueError:
            raise ValueError(f"Cannot convert {value} to {enum_type}")
    elif isinstance(value, str):
        v = value.strip()

        # Try lookup by name.
        try:
            return enum_type[v]
        except KeyError:
            pass

        # Try the string as integer value.
        try:
            return enum_type(int(v))
        except Exception:
            pass

        # Finally, try again with all upper case. Also, all "-" are replaced
        # with "_", but only if the result is unique.
        v2 = v.upper().replace("-", "_")
        matches = [e for e in enum_type if e.name.upper() == v2]
        if len(matches) == 1:
            return matches[0]

        raise ValueError(f"Cannot convert {value} to {enum_type}")

    raise ValueError(f"Invalid type for conversion to {enum_type}")


def enum_convert_list(enum_type: type[E], value: Any) -> list[E]:
    output: list[E] = []

    if isinstance(value, str):
        for part in value.split(","):
            part = part.strip()
            if not part:
                # Empty words are silently skipped.
                continue

            cases: Optional[list[E]] = None

            # Try to parse as a single enum value.
            try:
                cases = [enum_convert(enum_type, part)]
            except Exception:
                cases = None

            if part == "*":
                # Shorthand for the entire range (sorted by numeric values)
                cases = sorted(enum_type, key=lambda e: e.value)

            if cases is None:
                # Could not be parsed as single entry. Try to parse as range.

                def _range_endpoint(s: str) -> int:
                    try:
                        return int(s)
                    except Exception:
                        pass
                    return cast(int, enum_convert(enum_type, s).value)

                try:
                    # Try to detect this as range. Both end points may either by
                    # an integer or an enum name.
                    #
                    # Note that since we use "-" to denote the range, we cannot have
                    # a range that involves negative enum values (otherwise, enum_convert()
                    # is fine to parse a single enum from a negative number in a string).
                    start, end = [_range_endpoint(s) for s in part.split("-")]
                except Exception:
                    # Couldn't parse as range.
                    pass
                else:
                    # We have a range.
                    cases = None
                    for i in range(start, end + 1):
                        try:
                            e = enum_convert(enum_type, i)
                        except Exception:
                            # When specifying a range, then missing enum values are
                            # silently ignored. Note that as a whole, the range may
                            # still not be empty.
                            continue
                        if cases is None:
                            cases = []
                        cases.append(e)

            if cases is None:
                raise ValueError(f"Invalid test case id: {part}")

            output.extend(cases)
    elif isinstance(value, list):
        for idx, part in enumerate(value):
            # First, try to parse the list entry with plain enum_convert.
            cases = None
            try:
                cases = [enum_convert(enum_type, part)]
            except Exception:
                # Now, try to parse as a list (but only if we have a string, no lists in lists).
                if isinstance(part, str):
                    try:
                        cases = enum_convert_list(enum_type, part)
                    except Exception:
                        pass
            if not cases:
                raise ValueError(
                    f'list at index {idx} contains invalid value "{part}" for enum {enum_type}'
                )
            output.extend(cases)
    else:
        raise ValueError(f"Invalid {enum_type} value of type {type(value)}")

    return output


def json_parse_list(jstr: str, *, strict_parsing: bool = False) -> list[Any]:
    try:
        lst = json.loads(jstr)
    except ValueError:
        if strict_parsing:
            raise
        return []

    if not isinstance(lst, list):
        if strict_parsing:
            raise ValueError("JSON data does not contain a list")
        return []

    return lst


def dict_add_optional(vdict: dict[T1, T2], key: T1, val: Optional[T2]) -> None:
    if val is not None:
        vdict[key] = val


@typing.overload
def dict_get_typed(
    d: Mapping[Any, Any],
    key: Any,
    vtype: type[T],
    *,
    allow_missing: Literal[False] = False,
) -> T:
    pass


@typing.overload
def dict_get_typed(
    d: Mapping[Any, Any],
    key: Any,
    vtype: type[T],
    *,
    allow_missing: bool = False,
) -> Optional[T]:
    pass


def dict_get_typed(
    d: Mapping[Any, Any],
    key: Any,
    vtype: type[T],
    *,
    allow_missing: bool = False,
) -> Optional[T]:
    try:
        v = d[key]
    except KeyError:
        if allow_missing:
            return None
        raise KeyError(f'missing key "{key}"')
    if not isinstance(v, vtype):
        raise TypeError(f'key "{key}" expected type {vtype} but has value "{v}"')
    return v


def serialize_enum(
    data: Union[Enum, dict[Any, Any], list[Any], Any]
) -> Union[str, dict[Any, Any], list[Any], Any]:
    if isinstance(data, Enum):
        return data.name
    elif isinstance(data, dict):
        return {k: serialize_enum(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [serialize_enum(item) for item in data]
    else:
        return data


def dataclass_to_dict(obj: "DataclassInstance") -> dict[str, Any]:
    d = dataclasses.asdict(obj)
    return typing.cast(dict[str, Any], serialize_enum(d))


def dataclass_to_json(obj: "DataclassInstance") -> str:
    d = dataclass_to_dict(obj)
    return json.dumps(d)


# Takes a dataclass and the dict you want to convert from
# If your dataclass has a dataclass member, it handles that recursively
def dataclass_from_dict(cls: type[T], data: dict[str, Any]) -> T:
    if not is_dataclass(cls):
        raise ValueError(
            f"dataclass_from_dict() should only be used with dataclasses but is called with {cls}"
        )
    if not isinstance(data, dict):
        raise ValueError(
            f"requires a dictionary to in initialize dataclass {cls} but got {type(data)}"
        )
    for k in data:
        if not isinstance(k, str):
            raise ValueError(
                f"requires a strdict to in initialize dataclass {cls} but has key {type(k)}"
            )
    data = dict(data)
    create_kwargs = {}
    for field in fields(cls):
        if field.name not in data:
            if (
                field.default is dataclasses.MISSING
                and field.default_factory is dataclasses.MISSING
            ):
                raise ValueError(
                    f'Missing mandatory argument "{field.name}" for dataclass {cls}'
                )
            continue

        if not field.init:
            continue

        def convert_simple(ck_type: Any, value: Any) -> Any:
            if is_dataclass(ck_type) and isinstance(value, dict):
                return dataclass_from_dict(ck_type, value)
            if actual_type is None and issubclass(ck_type, Enum):
                return enum_convert(ck_type, value)
            if ck_type is float and isinstance(value, int):
                return float(value)
            return value

        actual_type = typing.get_origin(field.type)

        value = data.pop(field.name)

        converted = False

        if actual_type is typing.Union:
            # This is an Optional[]. We already have a value, we check for the requested
            # type. check_type() already implements this, but we need to also check
            # it here, for the dataclass/enum handling below.
            args = typing.get_args(field.type)
            ck_type = None
            if len(args) == 2:
                NoneType = type(None)
                if args[0] is NoneType:
                    ck_type = args[1]
                elif args[1] is NoneType:
                    ck_type = args[0]
            if ck_type is not None:
                value_converted = convert_simple(ck_type, value)
                converted = True
        elif actual_type is list:
            args = typing.get_args(field.type)
            if isinstance(value, list) and len(args) == 1:
                value_converted = [convert_simple(args[0], v) for v in value]
                converted = True

        if not converted:
            value_converted = convert_simple(field.type, value)

        if not check_type(value_converted, field.type):
            raise TypeError(
                f"Expected type '{field.type}' for attribute '{field.name}' but received type '{type(value)}' ({value})"
            )

        create_kwargs[field.name] = value_converted

    if data:
        raise ValueError(
            f"There are left over keys {list(data)} to create dataclass {cls}"
        )

    return cast(T, cls(**create_kwargs))


def check_type(
    value: typing.Any,
    type_hint: Union[type[typing.Any], typing._SpecialForm],
) -> bool:

    # Some naive type checking. This is used for ensuring that data classes
    # contain the expected types (see @strict_dataclass).
    #
    # That is most interesting, when we initialize the data class with
    # data from an untrusted source (like elements from a JSON parser).

    actual_type = typing.get_origin(type_hint)
    if actual_type is None:
        if isinstance(type_hint, str):
            raise NotImplementedError(
                f'Type hint "{type_hint}" as string is not implemented by check_type()'
            )

        if type_hint is typing.Any:
            return True
        return isinstance(value, typing.cast(Any, type_hint))

    if actual_type is typing.Union:
        args = typing.get_args(type_hint)
        return any(check_type(value, a) for a in args)

    if actual_type is list:
        args = typing.get_args(type_hint)
        (arg,) = args
        return isinstance(value, list) and all(check_type(v, arg) for v in value)

    if actual_type is dict or actual_type is Mapping:
        args = typing.get_args(type_hint)
        (arg_key, arg_val) = args
        return isinstance(value, dict) and all(
            check_type(k, arg_key) and check_type(v, arg_val) for k, v in value.items()
        )

    if actual_type is tuple:
        # https://docs.python.org/3/library/typing.html#annotating-tuples
        if not isinstance(value, tuple):
            return False
        args = typing.get_args(type_hint)
        if len(args) == 1 and args[0] == ():
            # This is an empty tuple tuple[()].
            return len(value) == 0
        if len(args) == 2 and args[1] is ...:
            # This is a tuple[T, ...].
            return all(check_type(v, args[0]) for v in value)
        return len(value) == len(args) and all(
            check_type(v, args[idx]) for idx, v in enumerate(value)
        )

    raise NotImplementedError(
        f'Type hint "{type_hint}" with origin type "{actual_type}" is not implemented by check_type()'
    )


def dataclass_check(
    instance: "DataclassInstance",
    *,
    with_post_check: bool = True,
) -> None:

    for field in dataclasses.fields(instance):
        value = getattr(instance, field.name)
        if not check_type(value, field.type):
            raise TypeError(
                f"Expected type '{field.type}' for attribute '{field.name}' but received type '{type(value)}' ({value})"
            )

    if with_post_check:
        # Normally, data classes support __post_init__(), which is called by __init__()
        # already. Add a way for a @strict_dataclass to add additional validation *after*
        # the original check.
        _post_check = getattr(type(instance), "_post_check", None)
        if _post_check is not None:
            _post_check(instance)


def strict_dataclass(cls: TCallable) -> TCallable:

    init = getattr(cls, "__init__")

    def wrapped_init(self: Any, *args: Any, **argv: Any) -> None:
        init(self, *args, **argv)
        dataclass_check(self)

    setattr(cls, "__init__", wrapped_init)
    return cls


def structparse_check_strdict(arg: Any, yamlpath: str) -> dict[str, Any]:
    """
    Checks that "args" is a strdict and returns a shallow copy
    of the dictionary.

    The usage is then to pop keys from the dictionary (structparse_pop_*())
    and at the end check that no more (unknown) keys are left (structparse_check_empty_dict()).
    """
    if not isinstance(arg, dict):
        raise ValueError(f'"{yamlpath}": expects a dictionary but got {type(arg)}')
    for k, v in arg.items():
        if not isinstance(k, str):
            raise ValueError(
                f'"{yamlpath}": expects all dictionary keys to be strings but got {type(k)}'
            )

    # We shallow-copy the dictionary, because the caller will remove entries
    # to find unknown entries (see _check_empty_dict()).
    return dict(arg)


def structparse_check_empty_dict(vdict: dict[str, Any], yamlpath: str) -> None:
    """
    Checks that "vdict" is empty or fail with an exception.

    The usage is to first shallow copy the dictionary (with structparse_check_strdict()),
    the pop all known keys (structparse_pop_*()), and finally check that no (unknown)
    keys are left. Possibly use this via "with structparse_with_strdict() as varg".
    """
    length = len(vdict)
    if length == 1:
        raise ValueError(f'"{yamlpath}": unknown key {repr(list(vdict)[0])}')
    if length > 1:
        raise ValueError(f'"{yamlpath}": unknown keys {list(vdict)}')


@dataclass(frozen=True)
class StructParseVarg:
    vdict: dict[str, Any]
    yamlpath: str
    check_empty: bool = dataclasses.field(default=True, init=False)

    def for_key(self, key: str) -> tuple[dict[str, Any], str, str]:
        """
        Returns a tuple of [vdict, yamlpath, key].

        This is for convenience, to pass to the structparse_pop_*() functions
        with less redundant typing. In particular, when wrapping lines, this
        only expands to one line instead of three, making it more compact to
        read.

        Example:

           foo = structparse_pop_str(*varg.for_key("foo"))
        """
        return self.vdict, self.yamlpath, key

    def for_name(self, key: str = "name") -> tuple[dict[str, Any], str, str]:
        """
        Same as for_key(), but defaults to a key "name".

        Example:

           foo = structparse_pop_str_name(*varg.for_name())
        """
        return self.vdict, self.yamlpath, key

    def skip_check_empty(self) -> None:
        """
        With structparse_with_strdict(), indicate that the final
        structparse_check_empty_dict() should be skipped.
        """
        object.__setattr__(self, "check_empty", False)


@contextlib.contextmanager
def structparse_with_strdict(
    arg: Any,
    yamlpath: str,
) -> typing.Generator[StructParseVarg, None, None]:
    """
    Context manager for parsing a strdict.

    arg: the argument, which is validated to be a string dictinary.
    yamlpath: the YAML path for "arg".

    Example:

        with structparse_with_strdict(arg, yamlpath) as varg:
            name = structparse_pop_str_name(*varg.for_name())
            foo = structparse_pop_int(*varg.for_key("foo"), default=None)

    Above is basically the same as

        vdict = structparse_check_strdict(arg, yamlpath)
        name = structparse_pop_str_name(vdict, yamlpath, "name")
        foo = structparse_pop_int(vdict, yamlpath, "foo", default=None)
        structparse_check_empty_dict(vdict)
    """
    vdict = structparse_check_strdict(arg, yamlpath)
    varg = StructParseVarg(vdict, yamlpath)
    yield varg
    if varg.check_empty:
        structparse_check_empty_dict(vdict, yamlpath)


def structparse_pop_str(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    default: Union[TOptionalStr, _MISSING_TYPE] = MISSING,
    empty_as_default: Optional[bool] = None,
    allow_empty: Optional[bool] = None,
    check: Optional[typing.Callable[[str], bool]] = None,
) -> Union[str, TOptionalStr]:
    """
    Pop "key" from "vdict", validates that it's a string and returns it.
    If "default" is given it is returned for missing keys. Otherwise,
    the key is mandatory.
    """
    # The arguments allow to carefully control what happens with empty
    # values. Usually, most parameters are unset by the caller, so we
    # must determine their actual values depending on the parameters
    # we have. It's chosen in a way, so that it makes the most sense
    # for the caller.
    if allow_empty is None:
        # "allow_empty" will default to True, if "empty_as_default" is set.
        if empty_as_default is not None:
            allow_empty = True
    if empty_as_default is None:
        # "empty_as_default" defaults to True, if "allow_empty" is True.
        empty_as_default = allow_empty is None or not allow_empty
    if allow_empty is None:
        # At this point, if "allow_empty" is still undecided, we allow
        # it if "empty_as_default" or if we have a "check".
        allow_empty = empty_as_default or check is not None
    if not allow_empty:
        empty_as_default = False

    v = vdict.pop(key, None)
    if v is not None and not isinstance(v, str):
        raise ValueError(f'"{yamlpath}.{key}": expects a string but got {v}')
    if v is None or (not v and empty_as_default):
        if isinstance(default, _MISSING_TYPE):
            raise ValueError(f'"{yamlpath}.{key}": mandatory key missing')
        return default
    if not v:
        if not allow_empty:
            raise ValueError(f'"{yamlpath}.{key}": cannot be an empty string')
    if check is not None:
        if not check(v):
            raise ValueError(f'"{yamlpath}.{key}": invalid string')
    return v


def structparse_pop_str_name(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str = "name",
    *,
    default: Union[TOptionalStr, _MISSING_TYPE] = MISSING,
) -> Union[str, TOptionalStr]:
    return structparse_pop_str(
        vdict,
        yamlpath,
        key=key,
        default=default,
        allow_empty=False,
    )


def structparse_pop_int(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    default: Union[TOptionalInt, _MISSING_TYPE] = MISSING,
    check: Optional[typing.Callable[[int], bool]] = None,
    description: str = "a number",
) -> Union[int, TOptionalInt]:
    v = vdict.pop(key, None)
    if v is None:
        if isinstance(default, _MISSING_TYPE):
            raise ValueError(
                f'"{yamlpath}.{key}": requires {description}',
            )
        return default
    try:
        val = int(v)
    except Exception:
        raise ValueError(f'"{yamlpath}.{key}": expects {description} but got {repr(v)}')
    if check is not None:
        if not check(val):
            raise ValueError(
                f'"{yamlpath}.{key}": expects {description} but got {repr(v)}'
            )
    return val


def structparse_pop_float(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    default: Union[TOptionalFloat, _MISSING_TYPE] = MISSING,
    check: Optional[typing.Callable[[float], bool]] = None,
    description: str = "a floating point number",
) -> Union[float, TOptionalFloat]:
    v = vdict.pop(key, None)
    if v is None:
        if isinstance(default, _MISSING_TYPE):
            raise ValueError(
                f'"{yamlpath}.{key}": requires {description}',
            )
        return default
    try:
        val = float(v)
    except Exception:
        raise ValueError(f'"{yamlpath}.{key}": expects {description} but got {repr(v)}')
    if check is not None:
        if not check(val):
            raise ValueError(
                f'"{yamlpath}.{key}": expects {description} but got {repr(v)}'
            )
    return val


def structparse_pop_bool(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    default: Union[TOptionalBool, _MISSING_TYPE] = MISSING,
    description: str = "a boolean",
) -> Union[bool, TOptionalBool]:
    v = vdict.pop(key, None)
    try:
        # Just like str_to_bool(), we accept "", "default", and "-1" as default
        # values (if `default` is not MISSING).
        return str_to_bool(v, on_default=default)
    except Exception:
        if v is None:
            raise ValueError(f'"{yamlpath}.{key}": requires {description}')
        raise ValueError(f'"{yamlpath}.{key}": expects {description} but got {repr(v)}')


@typing.overload
def structparse_pop_enum(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    enum_type: type[E],
    default: Union[E, _MISSING_TYPE] = MISSING,
) -> E:
    pass


@typing.overload
def structparse_pop_enum(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    enum_type: type[E],
    default: Literal[None],
) -> Optional[E]:
    pass


def structparse_pop_enum(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    enum_type: type[E],
    default: Union[Optional[E], _MISSING_TYPE] = MISSING,
) -> Optional[E]:
    v = vdict.pop(key, None)
    if v is None:
        if isinstance(default, _MISSING_TYPE):
            raise ValueError(
                f"\"{yamlpath}.{key}\": requires one of {', '.join(e.name for e in enum_type)}"
            )
        return default
    if isinstance(default, _MISSING_TYPE):
        default = None
    try:
        return enum_convert(enum_type, v, default=default)
    except Exception:
        raise ValueError(
            f"\"{yamlpath}.{key}\": requires one of {', '.join(e.name for e in enum_type)} but got {repr(v)}"
        )


def structparse_pop_list(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    allow_missing: Optional[bool] = None,
    allow_empty: bool = True,
) -> list[Any]:
    """
    Checks that "key" is a list (of anything) and returns a shallow copy of the
    list. This always returns a (potentially empty) list. By default, missing
    key and empty list is allowed, but that can be restricted with the
    "allow_missing" and "allow_empty" parameters.
    """
    if allow_missing is None:
        allow_missing = allow_empty
    v = vdict.pop(key, None)
    if v is None:
        if not allow_missing:
            raise ValueError(f'"{yamlpath}.{key}": mandatory list argument missing')
        # We never return None here. For many callers that is what we just
        # want. For callers that want to do something specific if the key is
        # unset, they should check first whether vdict contains the key.
        return []
    if not isinstance(v, list):
        raise ValueError(f'"{yamlpath}.{key}": requires a list but got {type(v)}')
    if not v:
        if not allow_empty:
            raise ValueError(f'"{yamlpath}.{key}": list cannot be empty')
    # Return a shallow copy of the list.
    return list(v)


def structparse_pop_obj(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    construct: typing.Callable[[int, str, Any], T],
    default: Union[T2, _MISSING_TYPE] = MISSING,
    construct_default: bool = False,
) -> Union[T, T2]:
    """
    Pops "key" from "vdict" and passes it to "construct" callback to parse
    and construct a result.

    By default, the key is mandatory. If "construct_default" is True,
    for missing keys we pass None to "construct". This allows to generate
    the callback a default value. Otherwise, if "default" is set, that
    is returned for missing keys.
    """
    v = vdict.pop(key, None)
    if not construct_default and v is None:
        if isinstance(default, _MISSING_TYPE):
            raise ValueError(f'"{yamlpath}.{key}": mandatory key missing')
        return default
    return construct(0, f"{yamlpath}.{key}", v)


def structparse_pop_objlist(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    construct: typing.Callable[[int, str, Any], T],
    allow_missing: Optional[bool] = None,
    allow_empty: bool = True,
) -> tuple[T, ...]:
    v = structparse_pop_list(
        vdict,
        yamlpath,
        key,
        allow_missing=allow_missing,
        allow_empty=allow_empty,
    )
    return tuple(
        construct(
            yamlidx2,
            f"{yamlpath}.{key}[{yamlidx2}]",
            arg2,
        )
        for yamlidx2, arg2 in enumerate(v)
    )


@typing.overload
def structparse_pop_objlist_to_dict(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    construct: typing.Callable[[int, str, Any], TStructParseBaseNamed],
    get_key: Literal[None] = None,
    allow_empty: bool = True,
    allow_duplicates: bool = False,
) -> dict[str, TStructParseBaseNamed]:
    pass


@typing.overload
def structparse_pop_objlist_to_dict(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    construct: typing.Callable[[int, str, Any], T],
    get_key: typing.Callable[[T], T2],
    allow_empty: bool = True,
    allow_duplicates: bool = False,
) -> dict[T2, T]:
    pass


def structparse_pop_objlist_to_dict(
    vdict: dict[str, Any],
    yamlpath: str,
    key: str,
    *,
    construct: typing.Callable[[int, str, Any], T],
    get_key: Optional[typing.Callable[[T], T2]] = None,
    allow_empty: bool = True,
    allow_duplicates: bool = False,
) -> dict[T2, T]:
    lst = structparse_pop_objlist(
        vdict,
        yamlpath,
        key,
        construct=construct,
        allow_empty=allow_empty,
    )
    result: dict[T2, tuple[int, T]] = {}
    for yamlidx2, item in enumerate(lst):
        if get_key is not None:
            item_key = get_key(item)
        else:
            if not isinstance(item, StructParseBaseNamed):
                raise RuntimeError(
                    f"list requires StructParseBaseNamed elements but we got {type(item)}"
                )
            item_key = typing.cast("T2", item.name)
        item2 = result.get(item_key, None)
        if item2 is not None:
            if allow_duplicates:
                # We allow duplicates. Last occurrence wins. We remove the old
                # entry (because the dict is sorted, and we want to preserve the
                # order.
                del result[item_key]
            else:
                if isinstance(item_key, Enum):
                    key_name = item_key.name
                else:
                    key_name = repr(item_key)
                raise ValueError(
                    f'"{yamlpath}.{key}[{yamlidx2}]": duplicate key {repr(key_name)} with "{yamlpath}.{key}[{item2[0]}]"'
                )
        result[item_key] = (yamlidx2, item)
    return {k: v[1] for k, v in result.items()}


@strict_dataclass
@dataclass(frozen=True, **KW_ONLY_DATACLASS)
class StructParseBase(abc.ABC):
    yamlpath: str
    yamlidx: int

    @abc.abstractmethod
    def serialize(self) -> Union[dict[str, Any], list[Any]]:
        pass

    def serialize_json(self) -> str:
        return json.dumps(self.serialize())


@strict_dataclass
@dataclass(frozen=True, **KW_ONLY_DATACLASS)
class StructParseBaseNamed(StructParseBase, abc.ABC):
    name: str

    def serialize(self) -> dict[str, Any]:
        return {
            "name": self.name,
        }


def repeat_for_same_result(fcn: TCallable) -> TCallable:
    # This decorator wraps @fcn and will call it (up to 10 times) until the
    # same result was returned twice in a row. The purpose is when we fetch
    # several pieces of information form the system, that can change at any
    # time. We would like to get a stable, self-consistent result.
    @functools.wraps(fcn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        result = None
        for i in range(10):
            new_result = fcn(*args, **kwargs)
            if i != 0 and result == new_result:
                return new_result
            result = new_result
        return result

    return typing.cast(TCallable, wrapped)


def etc_hosts_update_data(
    content: str,
    new_entries: Mapping[str, tuple[str, Optional[Iterable[str]]]],
) -> str:

    lineregex = re.compile(r"^\s*[a-fA-F0-9:.]+\s+([-a-zA-Z0-9_.]+)(\s+.*)?$")

    def _unpack(
        v: tuple[str, Optional[Iterable[str]]]
    ) -> Union[Literal[False], tuple[str, tuple[str, ...]]]:
        n, a = v
        if a is None:
            a = ()
        else:
            a = tuple(a)
        return n, a

    entries = {k: _unpack(v) for k, v in new_entries.items()}

    def _build_line(name: str, ipaddr: str, aliases: tuple[str, ...]) -> str:
        if aliases:
            s_aliases = f" {' '.join(aliases)}"
        else:
            s_aliases = ""
        return f"{ipaddr} {name}{s_aliases}"

    result = []
    for line in content.splitlines():
        m = lineregex.search(line)
        if m:
            name = m.group(1)
            entry = entries.get(name)
            if entry is None:
                pass
            elif entry is False:
                continue
            else:
                line = _build_line(name, *entry)
                entries[name] = False
        result.append(line)

    entries2 = [(k, v) for k, v in entries.items() if v is not False]
    if entries2:
        if result and result[-1] != "":
            result.append("")
        for name, entry in entries2:
            result.append(_build_line(name, *entry))

    if not result:
        return ""

    result.append("")
    return "\n".join(result)


def etc_hosts_update_file(
    new_entries: Mapping[str, tuple[str, Optional[Iterable[str]]]],
    filename: PathType = "/etc/hosts",
) -> str:
    try:
        with open(filename, "rb") as f:
            b_content = f.read()
    except Exception:
        b_content = b""

    new_content = etc_hosts_update_data(
        b_content.decode("utf-8", errors="surrogateescape"),
        new_entries,
    )

    with open(filename, "wb") as f:
        f.write(new_content.encode("utf-8", errors="surrogateescape"))

    return new_content


class Serial:
    def __init__(self, port: str, baudrate: int = 115200):
        import serial

        self.port = port
        self._ser = serial.Serial(port, baudrate=baudrate, timeout=0)
        self._buffer = ""

    @property
    def buffer(self) -> str:
        return self._buffer

    def close(self) -> None:
        self._ser.close()

    def send(self, msg: str, *, sleep: float = 1) -> None:
        logger.debug(f"serial[{self.port}]: send {repr(msg)}")
        self._ser.write(msg.encode("utf-8", errors="surrogateescape"))
        time.sleep(sleep)

    def read_all(self) -> str:
        maxsize = 1000000
        while True:
            buf: bytes = self._ser.read(maxsize)
            self._buffer += buf.decode("utf-8", errors="surrogateescape")
            if len(buf) < maxsize:
                return self._buffer

    def expect(
        self,
        pattern: Union[str, re.Pattern[str]],
        timeout: float = 30,
    ) -> str:
        import select

        end_timestamp = time.monotonic() + timeout
        first_run = True

        logger.debug(f"serial[{self.port}]: expect message {repr(pattern)}")

        if isinstance(pattern, str):
            # We use DOTALL like pexpect does.
            # If you need something else, compile the pattern yourself.
            #
            # See also https://pexpect.readthedocs.io/en/stable/overview.html#find-the-end-of-line-cr-lf-conventions
            pattern_re = re.compile(pattern, re.DOTALL)
        else:
            pattern_re = pattern

        while True:

            # First, read all data from the serial port that is currently available.
            while True:
                b: bytes = self._ser.read(100)
                if not b:
                    break
                s = b.decode("utf-8", errors="surrogateescape")
                logger.debug(
                    f"serial[{self.port}]: read buffer ({len(self._buffer)} + {len(s)} unicode characters): {repr(s)}"
                )
                self._buffer += s

            matches = re.finditer(pattern_re, self._buffer)
            for match in matches:
                end_idx = match.end()
                logger.debug(
                    f"serial[{self.port}]: found expected message {end_idx} unicode characters, {len(self._buffer) - end_idx} remaning"
                )
                self._buffer = self._buffer[end_idx:]
                return self._buffer

            if first_run:
                first_run = False
            else:
                remaining_time = end_timestamp - time.monotonic()
                if remaining_time <= 0:
                    logger.debug(
                        f"serial[{self.port}]: did not find expected message {repr(pattern)} (buffer content is {repr(self._buffer)})"
                    )
                    raise RuntimeError(
                        f"Did not receive expected message {repr(pattern)} within timeout (buffer content is {repr(self._buffer)})"
                    )
                _, _, _ = select.select([self._ser], [], [], remaining_time)

    def __enter__(self) -> "Serial":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional["TracebackType"],
    ) -> None:
        self._ser.close()


def _log_parse_level_str(lvl: str) -> Optional[int]:
    lvl2 = lvl.lower().strip()
    if lvl2:
        log_levels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        if lvl2 in log_levels:
            return log_levels[lvl2]
    return None


def log_parse_level(
    lvl: Optional[Union[int, bool, str]],
    *,
    default_level: int = logging.INFO,
) -> int:
    if lvl is None or (isinstance(lvl, str) and lvl.lower().strip() == ""):
        v = log_default_level()
        if v is not None:
            return v
        return default_level
    if isinstance(lvl, bool):
        return logging.DEBUG if lvl else logging.INFO
    if isinstance(lvl, int):
        return lvl
    if isinstance(lvl, str):
        v = _log_parse_level_str(lvl)
        if v is not None:
            return v
    raise ValueError(f"invalid log level {repr(lvl)}")


@functools.cache
def log_all_loggers() -> bool:
    # By default, the main application calls common.log_config_logger()
    # and configures only certain loggers ("myapp", "ktoolbox"). If
    # KTOOLBOX_ALL_LOGGERS is set to True, then instead the root logger
    # will be configured which may affect also other python modules.
    return str_to_bool(os.getenv("KTOOLBOX_ALL_LOGGERS"), False)


@functools.cache
def log_default_level() -> Optional[int]:
    # On the command line, various main programs allow to specify the log
    # level. If they leave it unspecified, the default can be configured via
    # "KTOOLBOX_LOGLEVEL" environment variable. If still unspecified, the
    # default is determined by the main application that calls
    # common.log_config_logger().
    v = os.getenv("KTOOLBOX_LOGLEVEL")
    if v is not None:
        return _log_parse_level_str(v)
    return None


if typing.TYPE_CHECKING:
    # https://github.com/python/cpython/issues/92128#issue-1222296106
    # https://github.com/python/typeshed/pull/5954#issuecomment-1114270968
    # https://mypy.readthedocs.io/en/stable/runtime_troubles.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime
    _LogStreamHandler = logging.StreamHandler[typing.TextIO]
else:
    _LogStreamHandler = logging.StreamHandler


class _LogHandler(_LogStreamHandler):
    def __init__(self, level: int):
        super().__init__()
        fmt = "%(asctime)s.%(msecs)03d %(levelname)-7s [th:%(thread)s]: %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
        formatter = logging.Formatter(fmt, datefmt)
        self.setLevel(level)
        self.setFormatter(formatter)

    def setLevelWithLock(self, *, level: int) -> None:
        self.acquire()
        try:
            self.setLevel(level)
        finally:
            self.release()


def log_config_logger(
    level: Optional[Union[int, bool, str]],
    *loggers: Union[str, logging.Logger],
    default_level: int = logging.INFO,
) -> None:
    level = log_parse_level(level, default_level=default_level)

    if log_all_loggers():
        # If the environment variable KTOOLBOX_ALL_LOGGERS is True,
        # we configure the root logger instead.
        loggers = ("",)

    for logger in loggers:
        if isinstance(logger, str):
            logger = logging.getLogger(logger)
        elif isinstance(logger, ExtendedLogger):
            logger = logger.wrapped_logger

        with common_lock:
            handler = iter_get_first(
                h for h in logger.handlers if isinstance(h, _LogHandler)
            )

            if handler is None:
                handler = _LogHandler(level=level)
                is_new_handler = True
            else:
                is_new_handler = False

            logger.setLevel(level)

            if is_new_handler:
                logger.addHandler(handler)
            else:
                handler.setLevelWithLock(level=level)


def log_argparse_add_argument_verbose(parser: "argparse.ArgumentParser") -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=None,
        help="Enable debug logging (overwrites KTOOLBOX_LOGLEVEL environment). Set KTOOLBOX_ALL_LOGGERS to configure all loggers.",
    )


def log_argparse_add_argument_verbosity(
    parser: "argparse.ArgumentParser",
    *,
    default: Optional[str] = None,
) -> None:
    if default is None:
        msg_default = "default: info, overwrites KTOOLBOX_LOGLEVEL environment"
    else:
        msg_default = f"default: {repr(default)}"
    parser.add_argument(
        "-v",
        "--verbosity",
        choices=["debug", "info", "warning", "error", "critical"],
        default=default,
        help=f"Set the logging level ({msg_default}). Set KTOOLBOX_ALL_LOGGERS to configure all loggers.",
    )


class ExtendedLogger(logging.Logger):
    """A wrapper around a logger class with additional API

    This is-a Logger, and it delegates almost everything to the intenal
    logger instance. It implements a few convenience methods on top,
    but it has no state of it's own. That means, as long as you call
    API of the Logger base class, there is no difference between calling
    an operation on the extended logger or the wrapped logger.
    """

    def __init__(self, logger: Union[str, logging.Logger]):
        if isinstance(logger, str):
            logger = logging.getLogger(logger)
        self.wrapped_logger = logger

    _EXTENDED_ATTRIBUTES = (
        "wrapped_logger",
        "error_and_exit",
    )

    def __getattribute__(self, name: str) -> Any:
        # ExtendedLogger is-a logging.Logger, but it delegates most calls to
        # the wrapped-logger (which is also a logging.Logger).
        if name in ExtendedLogger._EXTENDED_ATTRIBUTES:
            return object.__getattribute__(self, name)
        logger = object.__getattribute__(self, "wrapped_logger")
        return logger.__getattribute__(name)

    def error_and_exit(self, msg: str, *, exit_code: int = -1) -> typing.NoReturn:
        self.error(msg)
        sys.exit(exit_code)
