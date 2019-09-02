import re

from cfripper.config.logger import get_logger
from cfripper.model.rule_processor import Rule

logger = get_logger()


class SecretsRolesOverprivilegedRule(Rule):

    PROJECT_NAME_RE = r"([\w\*-]+)\.prod\.\*"
    SECRETS_TABLE = ':table/credential-store'

    def invoke(self, resources, parameters):
        for resource in resources.get("AWS::IAM::Role", []):
            self.process_resource(resource.logical_id, resource)

    def process_resource(self, logical_name, properties):
        if not properties:
            return

        if properties.policies and self._config.project_name:
            logger.info("Checking {}'s inline Policies".format(logical_name))

            self.check_inline_policies(logical_name, properties.policies)

    def check_inline_policies(self, logical_name_of_resource, policies):
        for policy in policies:
            for statement in policy.policy_document.statements:
                if self.SECRETS_TABLE in str(statement.resource):
                    self.__check_condition(
                        logical_name_of_resource,
                        policy.policy_name,
                        self._config.project_name,
                        statement
                    )

    def __check_condition(self, logical_name_of_resource, policy_name, project_name, statement):
        leading_keys = statement.condition.get('ForAllValues:StringLike', {}).get('dynamodb:LeadingKeys')
        if not leading_keys:
            reason = 'Mshell secrets role "{}" does not contain a condition in policy "{}"'.format(
                logical_name_of_resource,
                policy_name,
            )
            self.add_failure(type(self).__name__, reason)
            return

        for leading_key in leading_keys:
            try:
                if not isinstance(leading_key, str):
                    logger.warn(
                        f"{type(self).__name__}/{self._config.stack_name}/{self._config.service_name}"
                        " - Skipping validation: leading key is possibly a function."
                    )
                    continue
                cond_project_name = re.match(self.PROJECT_NAME_RE, leading_key).group(1)
            except AttributeError:
                reason = 'Mshell secrets role "{}" does not contain a valid condition in policy "{}"'.format(
                    logical_name_of_resource,
                    policy_name,
                )
                self.add_failure(type(self).__name__, reason)
                continue

            if project_name != cond_project_name:
                reason = 'Mshell secrets role contains an insecure condition "{}" not restricted to the correct project "{}" in policy "{}"'.format(
                    leading_key,
                    project_name,
                    policy_name,
                )
                self.add_failure(type(self).__name__, reason)
