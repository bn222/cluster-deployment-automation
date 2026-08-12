ARG OVNK_IMAGE
ARG OVNK_BUILDER_IMAGE
FROM $OVNK_BUILDER_IMAGE AS builder

ARG OVN_REMOVE_DEPS
ARG OVN_REPO
ARG OVN_REF
ARG OVNK_REPO
ARG OVNK_REF

RUN dnf install -y git go rpm-build
ENV PATH="/root/go/bin:${PATH}"

WORKDIR /root
RUN rm -rf /root/ovn && git clone ${OVN_REPO}
WORKDIR /root/ovn
RUN git checkout ${OVN_REF}
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
RUN ./boot.sh && ./configure && make dist -j$(nproc)

WORKDIR /root/ovn
RUN ./boot.sh && ./configure && make dist -j$(nproc) && \
     make rpm-fedora RPMBUILD_OPT="--without check --without sphinx"

# Clone ovn-kubernetes.
WORKDIR /root
RUN git clone ${OVNK_REPO}
WORKDIR /root/ovn-kubernetes
RUN git checkout ${OVNK_IMAGE_SHA}

# Copy the schema from OVN.
RUN cp /root/ovn/ovn-nb.ovsschema go-controller/pkg/nbdb/ovn-nb.ovsschema
RUN cp /root/ovn/ovn-sb.ovsschema go-controller/pkg/sbdb/ovn-sb.ovsschema

# Rebuild ovn-kubernetes with the new schema.
RUN cd go-controller; make modelgen && CGO_ENABLED=1 make

FROM $OVNK_IMAGE

COPY --from=builder /root/ovn/rpm/rpmbuild/RPMS/x86_64/ovn-*rpm /tmp/
# Force upgrade to use custom OVN rpms.
RUN rpm -Uhv --nodeps --force /tmp/ovn-*rpm

# Copy ovn-kubernetes binaries from the builder.
COPY --from=builder /root/ovn-kubernetes/go-controller/_output/go/bin/ovnkube /usr/bin/
COPY --from=builder /root/ovn-kubernetes/go-controller/_output/go/bin/ovnkube-identity /usr/bin/
COPY --from=builder /root/ovn-kubernetes/go-controller/_output/go/bin/ovn-kube-util /usr/bin/
COPY --from=builder /root/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/
COPY --from=builder /root/ovn-kubernetes/go-controller/_output/go/bin/ovnkube-trace /usr/bin/
COPY --from=builder /root/ovn-kubernetes/go-controller/_output/go/bin/ovnkube-observ /usr/bin/
