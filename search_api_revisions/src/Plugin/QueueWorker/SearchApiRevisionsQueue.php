<?php

namespace Drupal\search_api_revisions\Plugin\QueueWorker;

use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Queue\QueueWorkerBase;
use Drupal\search_api_revisions\Plugin\search_api\datasource\ContentEntityRevisions;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Processes search index.
 *
 * @QueueWorker(
 *   id = \Drupal\search_api_revisions\Plugin\QueueWorker\SearchApiRevisionsQueue::PLUGIN_ID,
 *   title = @Translation("Search api revisions queue"),
 *   cron = {"time" = 30}
 * )
 */
final class SearchApiRevisionsQueue extends QueueWorkerBase implements ContainerFactoryPluginInterface {

  public const PLUGIN_ID = 'search_api_revisions_queue';

  /**
   * The entity type manager service.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * The database.
   *
   * @var \Drupal\Core\Database\Connection
   */
  protected $database;

  /**
   * Constructs a new OrphanPurger instance.
   *
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param mixed $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager service.
   * @param \Drupal\Core\Database\Connection $database
   *   The database service.
   */
  public function __construct(array $configuration, $plugin_id, $plugin_definition, EntityTypeManagerInterface $entity_type_manager, Connection $database) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);
    $this->entityTypeManager = $entity_type_manager;
    $this->database = $database;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition): self {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('entity_type.manager'),
      $container->get('database')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function processItem($data) {
    $entity_type_id = $data['entity_type_id'] ?? 'node';
    if (!$this->entityTypeManager->hasDefinition($entity_type_id)) {
      return;
    }
    /** @var \Drupal\Core\Entity\ContentEntityInterface $entity */
    $entity = $this->entityTypeManager->getStorage($entity_type_id)->load($data['entity_id']);

    if ($entity) {
      $update_ids = [];

      $indexes = ContentEntityRevisions::getIndexesForEntity($entity);

      $entity_type = $entity->getEntityType();
      $entity_table = $entity_type->getRevisionTable();
      $entity_revision_key = $entity_type->getKey('revision');
      $entity_id_key = $entity_type->getKey('id');

      $select = $this->database->select($entity_table, 'et');
      $select->addField('et', $entity_revision_key, 'revision');
      $select->condition($entity_id_key, $entity->id());
      foreach ($select->execute()->fetchAll() as $item) {
        $update_ids[] = $entity->id() . ':' . $item->revision;
      }

      $datasource_id = 'entity_revision:' . $entity->getEntityTypeId();

      foreach ($indexes as $index) {
        $index->trackItemsUpdated($datasource_id, $update_ids);
      }
    }
  }

}
