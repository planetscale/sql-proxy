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

.PHONY: build build-image push deploy clean
all: build build-image push deploy clean

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

.PHONY: deploy
deploy: 
	@echo "==> Deploying ${NAME}"
	@psk staging aws useast1 2 apply -f deploy/deployment.yaml 
	# make sure to delete pods, so we new pods are created with the :latest image
	@psk staging aws useast1 2 delete pods -l "app=sql-proxy-server"

.PHONY: logs
logs: 
	@psk staging aws useast1 2 logs --tail 100 -l 'app=${NAME}' -f

.PHONY: status
status: 
	@psk staging aws useast1 2 get deployments/${NAME}
	@psk staging aws useast1 2 get pods -l 'app=${NAME}'
	@psk staging aws useast1 2 describe deployments/${NAME}


.PHONY: clean
clean:
	@echo "==> Cleaning artifacts"
	@rm ${NAME}
