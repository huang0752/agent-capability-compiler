"""Strict response models for the synthetic CRM."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict


class ResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Customer(ResponseModel):
    id: str
    tenant_id: str
    name: str
    industry: str
    owner: str


class Contact(ResponseModel):
    id: str
    tenant_id: str
    customer_id: str
    name: str
    email: str
    role: str


class Followup(ResponseModel):
    id: str
    tenant_id: str
    customer_id: str
    summary: str
    due_date: date
    status: Literal["open", "completed"]


class Todo(ResponseModel):
    id: str
    tenant_id: str
    customer_id: str
    title: str
    due_date: date
    completed: bool


__all__ = ["Contact", "Customer", "Followup", "Todo"]
