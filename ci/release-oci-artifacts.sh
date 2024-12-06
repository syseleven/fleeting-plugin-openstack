#!/usr/bin/env bash

set -eo pipefail

# convert 'dist/fleeting-plugin-{name}_{os}_{arch}_{arch_verson}/fleeting-plugin-openstack' to 'dist/{os}/{arch}/plugin'
for path in ./dist/fleeting-plugin-*/*; do
	dirname=$(dirname $(echo ${path#dist/}))
	IFS='_' read -ra parts <<<"${dirname}"

	os=${parts[1]}
	arch=${parts[2]%.exe}

	if [ "$arch" = "arm" ]; then
		arch="armv${parts[3]}"
	fi

	ext=""
	if [ "$os" = "windows" ]; then
		ext=".exe"
	fi

	mkdir -p "dist/${os}/${arch}/"
	mv "${path}" "dist/${os}/${arch}/plugin${ext}"
done

find ./dist

go install gitlab.com/gitlab-org/fleeting/fleeting-artifact/cmd/fleeting-artifact@latest

VERSION=${GITHUB_REF_NAME:=0.0.0-bleeding}

# login to registry
fleeting-artifact login -username "${GITHUB_ACTOR}" -password "${GITHUB_TOKEN}" "${REGISTRY}"

# releast artifact
IMAGE_DIGEST="$(fleeting-artifact release "${REGISTRY}/${IMAGE_NAME}:${VERSION#v}")"

# keyless sign
cosign sign "${IMAGE_DIGEST}"
