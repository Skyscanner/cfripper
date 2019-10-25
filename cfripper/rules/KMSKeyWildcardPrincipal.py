"""
Copyright 2018-2019 Skyscanner Ltd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import re

from pycfmodel.model.cf_model import CFModel

from ..model.rule import Rule


class KMSKeyWildcardPrincipal(Rule):

    REASON = "KMS Key policy {} should not allow wildcard principals"
    CONTAINS_WILDCARD_PATTERN = re.compile(r"^(\w*:)?\*$")

    def invoke(self, cfmodel: CFModel):
        for logical_id, resource in cfmodel.Resources.items():
            if resource.Type == "AWS::KMS::Key" and resource.Properties.KeyPolicy.allowed_principals_with(
                self.CONTAINS_WILDCARD_PATTERN
            ):
                self.add_failure(type(self).__name__, self.REASON.format(logical_id))
