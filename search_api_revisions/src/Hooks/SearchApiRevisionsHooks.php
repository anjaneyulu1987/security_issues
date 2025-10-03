<?php

declare(strict_types=1);

namespace Drupal\search_api_revisions\Hooks;

use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Queue\QueueFactory;
use Drupal\search_api_revisions\Plugin\QueueWorker\SearchApiRevisionsQueue;
use Drupal\search_api_revisions\Plugin\search_api\datasource\ContentEntityRevisions;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Hook bridges for search_api_revisions.
 */
final class SearchApiRevisionsHooks implements ContainerInjectionInterface {

  /**
   * Constructs a SearchApiRevisionsHooks.
   */
  public function __construct(
    protected EntityTypeManagerInterface $entityTypeManager,
    protected ImmutableConfig $config,
    protected QueueFactory $queueFactory,
  ) {
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new static(
      $container->get('entity_type.manager'),
      $container->get('config.factory')->get('search_api_revisions.settings'),
      $container->get('queue'),
    );
  }

  /**
   * Hook bridge for search_api_revisions_entity_insert().
   */
  public function entityInsert(EntityInterface $entity): void {
    $this->entityInsertOrUpdate($entity);
  }

  /**
   * Hook bridge for search_api_revisions_entity_update().
   */
  public function entityUpdate(EntityInterface $entity): void {
    $this->entityInsertOrUpdate($entity, TRUE);
  }

  /**
   * Called from hook_entity_insert and hook_entity_update.
   *
   * Adds entry for the new entity to the tracking table for
   * each index that tracks entities of this type.
   *
   * By setting the $entity->search_api_skip_tracking property to a true-like
   * value before this hook is invoked, you can prevent this behavior and make
   * the Search API Revisions ignore this new entity.
   */
  private function entityInsertOrUpdate(EntityInterface $entity, bool $update = FALSE): void {
    if (!($entity instanceof ContentEntityInterface) || $entity->search_api_skip_tracking) {
      return;
    }
    $indexes = ContentEntityRevisions::getIndexesForEntity($entity);
    if (!$indexes) {
      return;
    }

    $datasource_id = ContentEntityRevisions::getDatasourceIdForEntity($entity);

    foreach ($indexes as $index) {
      $index->trackItemsInserted($datasource_id, [
        ContentEntityRevisions::getItemIdForEntity($entity),
      ]);

      // For updates, index previous revisions if configured.
      if ($update && $this->config->get('index_previous_revisions')) {
        $this->trackPreviousRevisionsUpdated($entity);
      }
    }
  }

  /**
   * Marks all previous revisions of an entity as updated.
   *
   * This can be useful when indexing things like the published or default
   * revision status of a revision that need to be reindexed when new revisions
   * are created.
   */
  private function trackPreviousRevisionsUpdated(ContentEntityInterface $entity): void {
    // Queue the updates if configured.
    if ($this->config->get('queue')['items_update_queue'] ?? FALSE) {
      $queue = $this->queueFactory->get(SearchApiRevisionsQueue::PLUGIN_ID);
      $queue->createItem([
        'entity_id' => $entity->id(),
        'entity_type_id' => $entity->getEntityTypeId(),
      ]);
      return;
    }

    // Otherwise, immediately track all previous revisions as updated.
    $entityType = $entity->getEntityType();
    $query = $this->entityTypeManager->getStorage($entityType->id())
      ->getQuery()
      ->allRevisions()
      ->condition($entityType->getKey('id'), $entity->id())
      ->condition($entityType->getKey('revision'), $entity->getRevisionId(), '!=')
      ->accessCheck(FALSE);

    $entityIds = $query->execute();

    if (empty($entityIds)) {
      return;
    }
    $indexes = ContentEntityRevisions::getIndexesForEntity($entity);
    if (!$indexes) {
      return;
    }
    $datasourceId = ContentEntityRevisions::getDatasourceIdForEntity($entity);
    $itemIds = [];
    foreach ($entityIds as $revisionId => $entityId) {
      $itemIds[] = $entityId . ':' . $revisionId;
    }

    foreach ($indexes as $index) {
      $index->trackItemsUpdated($datasourceId, $itemIds);
    }
  }

  /**
   * Hook bridge for search_api_revisions_entity_predelete().
   *
   * Deletes all entries for this entity from the tracking table for each index
   * that tracks this entity type.
   *
   * This must be predelete because when using delete we have
   * no revisions in storage.
   */
  public function entityPreDelete(EntityInterface $entity): void {
    // Check if the entity is a content entity.
    if (!($entity instanceof ContentEntityInterface) || $entity->search_api_skip_tracking) {
      return;
    }
    $indexes = ContentEntityRevisions::getIndexesForEntity($entity);
    if (!$indexes) {
      return;
    }

    $datasource_id = ContentEntityRevisions::getDatasourceIdForEntity($entity);

    $entityType = $entity->getEntityType();
    $query = $this->entityTypeManager->getStorage($entityType->id())
      ->getQuery()
      ->allRevisions()
      ->condition($entityType->getKey('id'), $entity->id())
      ->accessCheck(FALSE);

    $entityIds = $query->execute();

    if (empty($entityIds)) {
      return;
    }

    $itemIds = [];
    foreach ($entityIds as $revision_id => $entity_id) {
      $itemIds[] = $entity_id . ':' . $revision_id;
    }

    foreach ($indexes as $index) {
      $index->trackItemsDeleted($datasource_id, $itemIds);
    }
  }

  /**
   * Hook bridge for search_api_revisions_entity_revision_delete().
   */
  public function entityRevisionDelete(EntityInterface $entity): void {
    if (!($entity instanceof ContentEntityInterface) || $entity->search_api_skip_tracking) {
      return;
    }
    $indexes = ContentEntityRevisions::getIndexesForEntity($entity);
    if (!$indexes) {
      return;
    }

    $datasource_id = ContentEntityRevisions::getDatasourceIdForEntity($entity);

    foreach ($indexes as $index) {
      $index->trackItemsDeleted($datasource_id, [
        ContentEntityRevisions::getItemIdForEntity($entity),
      ]);
    }
  }

}
