#!/bin/bash

set -xe

. /mnt/kgr-test-support/env.sh
. /mnt/kgr-test-support/lib.sh

skip_on_arch s390x ppc64le

# Due to lack of HW in the test env, resort to a simple modprobe test.
modprobe --allow-unsupported i915
