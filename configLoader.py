import yaml
from pydantic import ValidationError, BaseModel, ConfigDict
from yaml.nodes import ScalarNode, MappingNode
from typing import Dict, Any, Type, TypeVar
from logger import logger


class StrictBaseModel(BaseModel, frozen=True):
    model_config = ConfigDict(extra="forbid")


class LineNumberLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> Any:
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)  # type: ignore
            value = self.construct_object(value_node, deep=deep)  # type: ignore
            mapping[key] = value
            if isinstance(key_node, ScalarNode):
                mapping[f"_line_{key}"] = key_node.start_mark.line
        return mapping


def extract_field_lines(data: Dict[str, Any], prefix="") -> Dict[str, int]:  # type: ignore
    field_lines = {}
    for key, value in data.items():
        if key.startswith("_line_"):
            continue
        full_key = f"{prefix}.{key}" if prefix else key
        line_key = f"_line_{key}"
        if line_key in data:
            field_lines[full_key] = data[line_key]
        if isinstance(value, dict):
            field_lines.update(extract_field_lines(value, prefix=full_key))
    return field_lines


def clean_yaml_data(data: Dict[str, Any]) -> Dict[str, Any]:
    ret = {}
    for k, v in data.items():
        if k.startswith("_line_"):
            continue

        if isinstance(v, dict):
            ret[k] = clean_yaml_data(v)
        else:
            ret[k] = v
    return ret


T = TypeVar('T', bound=object)


def load(path: str, cls: Type[T]) -> T:
    with open(path) as f:
        yaml_str = f.read()
    parsed_data_with_lines = yaml.load(yaml_str, Loader=LineNumberLoader)
    field_lines = extract_field_lines(parsed_data_with_lines)
    parsed_data_clean = clean_yaml_data(parsed_data_with_lines)

    try:
        config = cls(**parsed_data_clean)
    except ValidationError as e:
        for err in e.errors():
            field = ".".join(err['loc'])  # type: ignore
            line = field_lines.get(field, "Unknown")
            logger.error_and_exit(f"Error in field '{field}': {err['msg']} (Line {line})")
        logger.error_and_exit("Got value error")
    return config
