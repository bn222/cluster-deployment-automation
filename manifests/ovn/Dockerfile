ARG OVNK_IMAGE
FROM $OVNK_IMAGE AS builder

ARG OVN_REMOVE_DEPS
ARG OVN_REPO
ARG OVN_BRANCH

RUN dnf install -y git rpm-build

WORKDIR /root
RUN rm -rf /root/ovn && git clone ${OVN_REPO}
WORKDIR /root/ovn
RUN git checkout ${OVN_BRANCH}
RUN git submodule update --init

# Remove non-essential dependencies.
RUN for dep in $OVN_REMOVE_DEPS; do \
        sed -i "/$dep/d" rhel/ovn-fedora.spec.in; \
    done

# Install essential dependencies.
RUN sed -e 's/@VERSION@/0.0.1/' rhel/ovn-fedora.spec.in > /tmp/ovn.spec
RUN dnf builddep -y /tmp/ovn.spec

# Build RPMS.
WORKDIR /root/ovn/ovs
RUN ./boot.sh && ./configure && make dist

WORKDIR /root/ovn
RUN ./boot.sh && ./configure && make dist && make rpm-fedora

FROM $OVNK_IMAGE

COPY --from=builder /root/ovn/rpm/rpmbuild/RPMS/x86_64/ovn-*rpm /tmp/
# Force upgrade to use custom OVN rpms.
RUN rpm -Uhv --nodeps --force /tmp/ovn-*rpm
