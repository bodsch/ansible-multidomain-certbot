#!/usr/bin/python3
# -*- coding: utf-8 -*-

# (c) 2021-2024, Bodo Schulz <bodo@boone-schulz.de>
# GNU General Public License version 3 (see LICENSE or https://opensource.org/license/gpl-3-0)
# SPDX-License-Identifier: GPL-3.0

from __future__ import absolute_import, division, print_function
import os

from ansible.module_utils.basic import AnsibleModule


class DomainCerts(object):
    """
    """

    def __init__(self, module):
        """
        """
        self.module = module

        self.path = module.params.get("path")
        self.file = module.params.get("file")
        self.certificates = module.params.get("certificates")

    def run(self):
        """
        """
        present = []
        misses = []

        for cert in self.certificates:
            # self.module.log(msg=f"   - cert: {cert}")
            domain = cert.get("domain", None)

            if domain:
                if os.path.exists(os.path.join(self.path, domain, self.file)):
                    present.append(domain)
                else:
                    misses.append(domain)
            else:
                self.module.log(msg=f"ERROR: missing name in {cert}")
                pass

        return dict(
            changed=False,
            failed=False,
            certificate_present=present,
            certificate_miss=misses
        )


def main():
    specs = dict(
        path=dict(
            required=True,
            type="str"
        ),
        file=dict(
            required=True,
            type="str"
        ),
        certificates=dict(
            required=True,
            type="list"
        )
    )

    module = AnsibleModule(
        argument_spec=specs,
        supports_check_mode=True,
    )

    p = DomainCerts(module)
    result = p.run()

    # module.log(msg="= result: {}".format(result))
    module.exit_json(**result)


if __name__ == '__main__':
    main()