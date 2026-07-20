#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, nested_list_fn, run_components
from ocinferno.modules.generative_ai_agent.utilities.helpers import (
    GenerativeAiAgentAgentEndpointsResource,
    GenerativeAiAgentAgentsResource,
    GenerativeAiAgentKnowledgeBasesResource,
    GenerativeAiAgentToolsResource,
)


def _add_extra_args(parser):
    parser.add_argument("--agent-id", default="", help="Only enumerate tools for this agent OCID")


COMPONENTS = [
    Component("agents", GenerativeAiAgentAgentsResource, help_text="Enumerate agents", cache_table="generative_ai_agent_agents"),
    Component("agent_endpoints", GenerativeAiAgentAgentEndpointsResource, help_text="Enumerate agent-endpoints", cache_table="generative_ai_agent_agent_endpoints"),
    Component("knowledge_bases", GenerativeAiAgentKnowledgeBasesResource, help_text="Enumerate knowledge-bases", cache_table="generative_ai_agent_knowledge_bases"),
    Component("tools", GenerativeAiAgentToolsResource, help_text="Enumerate tools", cache_table="generative_ai_agent_tools",
              list_fn=nested_list_fn(
                  parent_resource_cls=GenerativeAiAgentAgentsResource,
                  parent_id_field="agent_id",
                  manual_parent_arg="agent_id",
              )),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_generative_ai_agent",
        description="Enumerate Generative AI Agents resources",
        add_extra_args=_add_extra_args,
    )
