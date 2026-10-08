const SoarKnowledgeBase = require('../../models/SoarKnowledgeBase');
const { log: auditLog } = require('../auditService');

/**
 * Knowledge Base Service — Manages standardized incident response playbooks,
 * resolution procedures, investigation notes, and MITRE mapping repository.
 */
const knowledgeBaseService = {
  /**
   * Creates a new knowledge base article
   */
  async createArticle({
    organization_id,
    title,
    summary = null,
    procedures = [],
    investigation_notes = null,
    resolution_summary = null,
    lessons_learned = null,
    mitre_mappings = [],
    tags = [],
    linked_case_ids = [],
    linked_playbook_ids = [],
    created_by = null
  }, client = null) {
    const article = await SoarKnowledgeBase.create({
      organization_id,
      title,
      summary,
      procedures,
      investigation_notes,
      resolution_summary,
      lessons_learned,
      mitre_mappings,
      tags,
      linked_case_ids,
      linked_playbook_ids,
      created_by
    }, client);

    await auditLog({
      organization_id,
      user_id: created_by,
      action: 'SOAR_KNOWLEDGE_BASE_CREATED',
      resource_type: 'soar_knowledge_base',
      resource_id: article.id,
      details: { title: article.title, tags: article.tags }
    });

    return article;
  },

  /**
   * Retrieves article by ID with tenant isolation
   */
  async getArticleById(id, organizationId, client = null) {
    return await SoarKnowledgeBase.findById(id, organizationId, client);
  },

  /**
   * Lists / searches articles with filters
   */
  async listArticles(organizationId, filters = {}, client = null) {
    return await SoarKnowledgeBase.findMany({
      ...filters,
      organization_id: organizationId
    }, client);
  },

  /**
   * Updates an article
   */
  async updateArticle(id, organizationId, updates = {}, userId = null, client = null) {
    const updated = await SoarKnowledgeBase.update(id, organizationId, updates, client);
    if (!updated) {
      throw new Error(`Knowledge base article "${id}" not found`);
    }

    await auditLog({
      organization_id: organizationId,
      user_id: userId,
      action: 'SOAR_KNOWLEDGE_BASE_UPDATED',
      resource_type: 'soar_knowledge_base',
      resource_id: id,
      details: { updated_fields: Object.keys(updates) }
    });

    return updated;
  },

  /**
   * Deletes an article
   */
  async deleteArticle(id, organizationId, userId = null, client = null) {
    const deleted = await SoarKnowledgeBase.delete(id, organizationId, client);
    if (!deleted) {
      throw new Error(`Knowledge base article "${id}" not found`);
    }

    await auditLog({
      organization_id: organizationId,
      user_id: userId,
      action: 'SOAR_KNOWLEDGE_BASE_DELETED',
      resource_type: 'soar_knowledge_base',
      resource_id: id,
      details: { title: deleted.title }
    });

    return deleted;
  },

  /**
   * Links a case to a knowledge base record
   */
  async linkCase(id, organizationId, caseId, client = null) {
    return await SoarKnowledgeBase.linkCase(id, organizationId, caseId, client);
  },

  /**
   * Links a playbook to a knowledge base record
   */
  async linkPlaybook(id, organizationId, playbookId, client = null) {
    return await SoarKnowledgeBase.linkPlaybook(id, organizationId, playbookId, client);
  }
};

module.exports = knowledgeBaseService;
