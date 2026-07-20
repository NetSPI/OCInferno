#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class GenerativeAiAgentAgentsResource(OciListResource):
    CLIENT_CLS = oci.generative_ai_agent.GenerativeAiAgentClient
    SERVICE_NAME = "Generative AI Agents"
    TABLE_NAME = "generative_ai_agent_agents"
    LIST_METHOD = "list_agents"
    GET_METHOD = "get_agent"
    GET_ID_PARAM = "agent_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
        "knowledge_base_ids",
        "welcome_message",
        "llm_config",
    ]


class GenerativeAiAgentAgentEndpointsResource(OciListResource):
    CLIENT_CLS = oci.generative_ai_agent.GenerativeAiAgentClient
    SERVICE_NAME = "Generative AI Agents"
    TABLE_NAME = "generative_ai_agent_agent_endpoints"
    LIST_METHOD = "list_agent_endpoints"
    GET_METHOD = "get_agent_endpoint"
    GET_ID_PARAM = "agent_endpoint_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "agent_id",
        "content_moderation_config",
        "guardrail_config",
        "should_enable_session",
        "should_enable_trace",
    ]


class GenerativeAiAgentKnowledgeBasesResource(OciListResource):
    CLIENT_CLS = oci.generative_ai_agent.GenerativeAiAgentClient
    SERVICE_NAME = "Generative AI Agents"
    TABLE_NAME = "generative_ai_agent_knowledge_bases"
    LIST_METHOD = "list_knowledge_bases"
    GET_METHOD = "get_knowledge_base"
    GET_ID_PARAM = "knowledge_base_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
        "lifecycle_details",
        "time_updated",
    ]


class GenerativeAiAgentToolsResource(OciListResource):
    CLIENT_CLS = oci.generative_ai_agent.GenerativeAiAgentClient
    SERVICE_NAME = "Generative AI Agents"
    TABLE_NAME = "generative_ai_agent_tools"
    LIST_METHOD = "list_tools"
    GET_METHOD = "get_tool"
    GET_ID_PARAM = "tool_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "agent_id",
        "tool_config",
        "description",
    ]
