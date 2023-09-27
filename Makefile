# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CMDS=pxplugin
PKG = github.com/portworx/windows-csi-driver
GINKGO_FLAGS = -ginkgo.v
GO111MODULE = on
GOPATH ?= $(shell go env GOPATH)
GOBIN ?= $(GOPATH)/bin
DOCKER_CLI_EXPERIMENTAL = enabled
IMAGENAME ?= pxplugin
export GOPATH GOBIN GO111MODULE DOCKER_CLI_EXPERIMENTAL

include release-tools/build.make

GIT_COMMIT ?= $(shell git rev-parse HEAD)
REGISTRY ?= docker.io/portworx/windows-csi-driver
REGISTRY_NAME = $(shell echo $(REGISTRY) | sed "s/.azurecr.io//g")
IMAGE_VERSION ?= v0.1.pxwindriver
VERSION ?= latest
# Use a custom version for E2E tests if we are testing in CI
ifdef CI
ifndef PUBLISH
override IMAGE_VERSION := e2e-$(GIT_COMMIT)
endif
endif
IMAGE_TAG = $(REGISTRY)/$(IMAGENAME):$(IMAGE_VERSION)
IMAGE_TAG_LATEST = $(REGISTRY)/$(IMAGENAME):latest
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS = -X ${PKG}/pkg/portworx.driverVersion=${IMAGE_VERSION} -X ${PKG}/pkg/portworx.gitCommit=${GIT_COMMIT} -X ${PKG}/pkg/portworx.buildDate=${BUILD_DATE}
EXT_LDFLAGS = -s -w -extldflags "-static"
E2E_HELM_OPTIONS ?= --set image.pwx.repository=$(REGISTRY)/$(IMAGENAME) --set image.pwx.tag=$(IMAGE_VERSION) --set controller.dnsPolicy=ClusterFirstWithHostNet --set linux.dnsPolicy=ClusterFirstWithHostNet
E2E_HELM_OPTIONS += ${EXTRA_HELM_OPTIONS}
# Generate all combination of all OS, ARCH, and OSVERSIONS for iteration
ALL_OS = windows
ALL_ARCH.windows = amd64
ALL_OSVERSIONS.windows := 1809 20H2 ltsc2022
ALL_OS_ARCH.windows = $(foreach arch, $(ALL_ARCH.windows), $(foreach osversion, ${ALL_OSVERSIONS.windows}, windows-${osversion}-${arch}))
ALL_OS_ARCH = $(foreach os, $(ALL_OS), ${ALL_OS_ARCH.${os}})

# The current context of image building
# The architecture of the image
ARCH ?= amd64
# OS Version for the Windows images: 1809, 1903, 1909, 2004
OSVERSION ?= 1809
# Output type of docker buildx build
OUTPUT_TYPE ?= registry

.EXPORT_ALL_VARIABLES:

all: pxplugin

.PHONY: update
update:
	hack/update-dependencies.sh
	hack/verify-update.sh

.PHONY: verify
verify: unit-test
	hack/verify-all.sh

.PHONY: unit-test
unit-test:
	go test -v -race ./pkg/... ./test/utils/credentials

.PHONY: sanity-test
sanity-test: pxplugin
	test/sanity/run-test.sh

.PHONY: integration-test
integration-test: pxplugin
	sudo -E env "PATH=$$PATH" bash test/integration/run-test.sh

.PHONY: deploy-kind
deploy-kind:
	test/utils/deploy-kind.sh

.PHONY: e2e-test
e2e-test:
	if [ ! -z "$(EXTERNAL_E2E_TEST)" ]; then \
		bash ./test/external-e2e/run.sh;\
	else \
		go test -v -timeout=0 ./test/e2e ${GINKGO_FLAGS};\
	fi

.PHONY: e2e-bootstrap
e2e-bootstrap: install-helm
	docker pull $(IMAGE_TAG) || make container-all push-manifest
ifdef TEST_WINDOWS
	helm upgrade csi-driver-smb charts/$(VERSION)/csi-driver-smb --namespace kube-system --wait --timeout=15m -v=5 --debug --install \
		${E2E_HELM_OPTIONS} \
		--set windows.enabled=true \
		--set linux.enabled=false \
		--set controller.replicas=1 \
		--set controller.logLevel=6 \
		--set node.logLevel=6
else
	helm upgrade csi-driver-smb charts/$(VERSION)/csi-driver-smb --namespace kube-system --wait --timeout=15m -v=5 --debug --install \
		${E2E_HELM_OPTIONS}
endif

.PHONY: install-helm
install-helm:
	curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash

.PHONY: e2e-teardown
e2e-teardown:
	helm delete csi-driver-smb --namespace kube-system

.PHONY: pxplugin
pxplugin:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -a -ldflags "${LDFLAGS} ${EXT_LDFLAGS}" -mod vendor -o _output/${ARCH}/pxplugin ./cmd/pxplugin

.PHONY: pxplugin-armv7
pxplugin-armv7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -a -ldflags "${LDFLAGS} ${EXT_LDFLAGS}" -mod vendor -o _output/arm/v7/pxplugin ./cmd/pxplugin

.PHONY: pxplugin-windows
pxplugin-windows:
	CGO_ENABLED=0 GOOS=windows go build -a -ldflags "${LDFLAGS} ${EXT_LDFLAGS}" -mod vendor -o _output/${ARCH}/pxplugin.exe ./cmd/pxplugin

.PHONY: pxplugin-darwin
pxplugin-darwin:
	CGO_ENABLED=0 GOOS=darwin go build -a -ldflags "${LDFLAGS} ${EXT_LDFLAGS}" -mod vendor -o _output/${ARCH}/pxplugin ./cmd/pxplugin

.PHONY: container
container: pxplugin
	docker build --no-cache -t $(IMAGE_TAG) --output=type=docker -f ./cmd/pxplugin/Dockerfile .

.PHONY: container-linux
container-linux:
	docker buildx build --pull --output=type=$(OUTPUT_TYPE) --platform="linux/$(ARCH)" \
		-t $(IMAGE_TAG)-linux-$(ARCH) --build-arg ARCH=$(ARCH) -f ./cmd/pxplugin/Dockerfile .

.PHONY: container-linux-armv7
container-linux-armv7:
	docker buildx build --pull --output=type=$(OUTPUT_TYPE) --platform="linux/arm/v7" \
		-t $(IMAGE_TAG)-linux-arm-v7 --build-arg ARCH=arm/v7 -f ./cmd/pxplugin/Dockerfile .

.PHONY: container-windows
container-windows:
	docker buildx build --pull --output=type=$(OUTPUT_TYPE) --platform="windows/$(ARCH)" \
		 -t $(IMAGE_TAG)-windows-$(OSVERSION)-$(ARCH) --build-arg OSVERSION=$(OSVERSION) \
		 --build-arg ARCH=$(ARCH) -f ./cmd/pxplugin/Dockerfile.Windows .

.PHONY: container-all
container-all: pxplugin-windows
	docker buildx rm container-builder || true
	docker buildx create --use --name=container-builder
	# enable qemu for arm64 build
	# https://github.com/docker/buildx/issues/464#issuecomment-741507760
	docker run --privileged --rm tonistiigi/binfmt --uninstall qemu-aarch64,arm
	docker run --rm --privileged tonistiigi/binfmt --install all
	for arch in $(ALL_ARCH.linux); do \
		ARCH=$${arch} $(MAKE) pxplugin; \
		ARCH=$${arch} $(MAKE) container-linux; \
	done
	$(MAKE) pxplugin-armv7
	$(MAKE) container-linux-armv7
	for osversion in $(ALL_OSVERSIONS.windows); do \
		OSVERSION=$${osversion} $(MAKE) container-windows; \
	done

.PHONY: push-manifest
push-manifest:
	docker manifest create --amend $(IMAGE_TAG) $(foreach osarch, $(ALL_OS_ARCH), $(IMAGE_TAG)-${osarch})
	# add "os.version" field to windows images (based on https://github.com/kubernetes/kubernetes/blob/master/build/pause/Makefile)
	set -x; \
	for arch in $(ALL_ARCH.windows); do \
		for osversion in $(ALL_OSVERSIONS.windows); do \
			BASEIMAGE=mcr.microsoft.com/windows/nanoserver:$${osversion}; \
			full_version=`docker manifest inspect $${BASEIMAGE} | jq -r '.manifests[0].platform["os.version"]'`; \
			docker manifest annotate --os windows --arch $${arch} --os-version $${full_version} $(IMAGE_TAG) $(IMAGE_TAG)-windows-$${osversion}-$${arch}; \
		done; \
	done
	docker manifest push --purge $(IMAGE_TAG)
ifdef PUBLISH
	docker manifest create $(IMAGE_TAG_LATEST) $(foreach osarch, $(ALL_OS_ARCH), $(IMAGE_TAG)-${osarch})
	set -x; \
	for arch in $(ALL_ARCH.windows); do \
		for osversion in $(ALL_OSVERSIONS.windows); do \
			BASEIMAGE=mcr.microsoft.com/windows/nanoserver:$${osversion}; \
			full_version=`docker manifest inspect $${BASEIMAGE} | jq -r '.manifests[0].platform["os.version"]'`; \
			docker manifest annotate --os windows --arch $${arch} --os-version $${full_version} $(IMAGE_TAG_LATEST) $(IMAGE_TAG)-windows-$${osversion}-$${arch}; \
		done; \
	done
	docker manifest inspect $(IMAGE_TAG_LATEST)
endif

.PHONY: push-latest
push-latest:
ifdef CI
	docker manifest push --purge $(IMAGE_TAG_LATEST)
else
	docker push $(IMAGE_TAG_LATEST)
endif

.PHONY: install-smb-provisioner
install-smb-provisioner:
	kubectl delete secret smbcreds --ignore-not-found
	kubectl create secret generic smbcreds --from-literal username=USERNAME --from-literal password="PASSWORD" --from-literal mountOptions="dir_mode=0777,file_mode=0777,uid=0,gid=0,mfsymlinks"
ifdef TEST_WINDOWS
	kubectl apply -f deploy/example/smb-provisioner/smb-server-lb.yaml
else
	kubectl apply -f deploy/example/smb-provisioner/smb-server.yaml
endif

.PHONY: create-metrics-svc
create-metrics-svc:
	kubectl apply -f deploy/example/metrics/csi-smb-controller-svc.yaml
