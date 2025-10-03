<?php

namespace Drupal\search_api_revisions\Plugin\search_api\datasource;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\Query\QueryInterface;
use Drupal\Core\TypedData\ComplexDataInterface;
use Drupal\search_api\Entity\Index;
use Drupal\search_api\Plugin\search_api\datasource\ContentEntity;
use Drupal\search_api\SearchApiException;

/**
 * Represents a datasource which exposes the content entities.
 *
 * @SearchApiDatasource(
 *   id = \Drupal\search_api_revisions\Plugin\search_api\datasource\ContentEntityRevisions::PLUGIN_ID,
 *   deriver = "Drupal\search_api_revisions\Plugin\search_api\datasource\ContentEntityRevisionsDeriver"
 * )
 */
class ContentEntityRevisions extends ContentEntity {

  public const PLUGIN_ID = 'entity_revision';

  /**
   * {@inheritdoc}
   */
  public function loadMultiple(array $ids) {
    /** @var \Drupal\Core\Entity\ContentEntityInterface[] $items */
    $items = [];
    /** @var \Drupal\Core\Entity\RevisionableStorageInterface $entityStorage */
    $entityStorage = $this->getEntityStorage();
    foreach ($ids as $item_id) {
      $pos = strrpos($item_id, ':');
      // This can only happen if someone passes an invalid ID, since we always
      // include a language code. Still, no harm in guarding against bad input.
      if ($pos === FALSE) {
        continue;
      }
      /* $entity_id = substr($item_id, 0, $pos); */
      $revision_id = substr($item_id, $pos + 1);

      if ($entity_revision = $entityStorage->loadRevision($revision_id)) {
        $items[$item_id] = $entity_revision->getTypedData();
      }
    }

    return $items;
  }

  /**
   * {@inheritdoc}
   */
  public function getItemUrl(ComplexDataInterface $item) {
    if ($entity = $this->getEntity($item)) {
      if ($entity->hasLinkTemplate('revision')) {
        return $entity->toUrl('revision');
      }
    }
    // Fallback to canonical URL.
    return parent::getItemUrl($item);
  }

  /**
   * {@inheritdoc}
   */
  public function getItemId(ComplexDataInterface $item) {
    if ($entity = $this->getEntity($item)) {
      $enabled_bundles = $this->getBundles();
      if (isset($enabled_bundles[$entity->bundle()])) {
        $revision_key = $this->getEntityType()->getKey('revision');
        return $entity->id() . ':' . $entity->{$revision_key};
      }
    }
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function getPartialItemIds($page = NULL, ?array $bundles = NULL, ?array $languages = NULL) {
    $query = $this->getPartialItemIdsQuery($page, $bundles, $languages);
    $entity_ids = $query->execute();

    if (!$entity_ids) {
      return NULL;
    }

    $item_ids = [];
    foreach ($entity_ids as $revision_id => $entity_id) {
      $item_ids[] = $entity_id . ':' . $revision_id;
    }

    return $item_ids;
  }

  /**
   * Get a query for getPartialItemIds.
   */
  protected function getPartialItemIdsQuery($page = NULL, ?array $bundles = NULL, ?array $languages = NULL): QueryInterface {
    $query = $this->getEntityStorage()
      ->getQuery()
      ->allRevisions()
      ->accessCheck(FALSE);

    // We want to determine all entities of either one of the given bundles OR
    // one of the given languages. That means we can't just filter for $bundles
    // if $languages is given. Instead, we have to filter for all bundles we
    // might want to include and later sort out those for which we want only the
    // translations in $languages and those (matching $bundles) where we want
    // all revisions.
    if ($this->hasBundles()) {
      $bundle_property = $this->getEntityType()->getKey('bundle');
      if ($bundles && !$languages) {
        $query->condition($bundle_property, $bundles, 'IN');
      }
      else {
        $enabled_bundles = array_keys($this->getBundles());
        // Since this is also called for removed bundles/languages,
        // $enabled_bundles might not include $bundles.
        if ($bundles) {
          $enabled_bundles = array_unique(array_merge($bundles, $enabled_bundles));
        }
        if (count($enabled_bundles) < count($this->getEntityBundles())) {
          $query->condition($bundle_property, $enabled_bundles, 'IN');
        }
      }
    }

    if (isset($page)) {
      $page_size = $this->getConfigValue('tracking_page_size');
      $query->range($page * $page_size, $page_size);
    }
    return $query;
  }

  /**
   * {@inheritdoc}
   */
  public static function getIndexesForEntity(ContentEntityInterface $entity) {
    $datasource_id = self::getDatasourceIdForEntity($entity);
    $entity_bundle = $entity->bundle();
    $has_bundles = $entity->getEntityType()->hasKey('bundle');

    // Needed for PhpStorm. See https://youtrack.jetbrains.com/issue/WI-23395.
    /** @var \Drupal\search_api\IndexInterface[] $indexes */
    $indexes = Index::loadMultiple();

    foreach ($indexes as $index_id => $index) {
      // Filter our indexes that don't contain the datasource in question.
      if (!$index->isValidDatasource($datasource_id)) {
        unset($indexes[$index_id]);
      }
      elseif ($has_bundles) {
        // If the entity type supports bundles, we also have to filter out
        // indexes that exclude the entity's bundle.
        try {
          $config = $index->getDatasource($datasource_id)->getConfiguration();
          $default = !empty($config['bundles']['default']);
          $bundle_set = in_array($entity_bundle, array_filter($config['bundles']['selected'], function ($data) {
            return !empty($data);
          }));
          if ($default == $bundle_set) {
            unset($indexes[$index_id]);
          }
        }
        catch (SearchApiException $e) {
          unset($indexes[$index_id]);
        }
      }
    }

    return $indexes;
  }

  /**
   * Gets a data-source ID for an entity.
   */
  public static function getDatasourceIdForEntity(ContentEntityInterface $entity): string {
    return 'entity_revision:' . $entity->getEntityTypeId();
  }

  /**
   * Gets the item ID for an entity.
   */
  public static function getItemIdForEntity(ContentEntityInterface $entity): string {
    return \sprintf('%s:%s', $entity->id(), $entity->getRevisionId());
  }

}
