VERSION := $(shell git rev-parse --short=7 HEAD 2>/dev/null)
GITCOMMIT_LONG := $(shell git rev-parse HEAD 2>/dev/null)

REPO=us.gcr.io/planetscale-dev
NAME=sql-proxy-server

ifeq ($(strip $(shell git status --porcelain 2>/dev/null)),)
  GIT_TREE_STATE=clean
else
  GIT_TREE_STATE=dirty
endif

COMMIT ?= $(shell git rev-parse HEAD)
LDFLAGS ?= -X main.commit=${GITCOMMIT_LONG} -X main.gitTreeState=${GIT_TREE_STATE}

.PHONY: build build-image push
all: build build-image push

.PHONY: build
build:
	@echo "==> Building ${NAME} binary "
	@env GOOS=linux GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o ${NAME}


.PHONY: build-image
build-image:  build
	@echo "==> Building docker image ${REPO}/${NAME}:$(VERSION)"
	@docker build -t ${REPO}/${NAME}:$(VERSION) .

.PHONY: push
push: 
	@echo "==> Pushing docker image ${REPO}/${NAME}:$(VERSION)"
	@docker tag ${REPO}/${NAME}:$(VERSION) ${REPO}/${NAME}:latest
	@docker push ${REPO}/${NAME}:latest
	@docker push ${REPO}/${NAME}:$(VERSION)
