<?php

namespace Drupal\search_api_revisions\Plugin\search_api\processor;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\TypedData\ComplexDataInterface;
use Drupal\search_api\Datasource\DatasourceInterface;
use Drupal\search_api\Item\ItemInterface;
use Drupal\search_api\Plugin\search_api\datasource\ContentEntity;
use Drupal\search_api\Processor\ProcessorPluginBase;
use Drupal\search_api\Processor\ProcessorProperty;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Adds an additional field containing the term parents.
 *
 * @SearchApiProcessor(
 *   id = "content_moderation_state",
 *   label = @Translation("Content moderation state"),
 *   description = @Translation("Adds all content moderation states found on node."),
 *   stages = {
 *     "add_properties" = 0,
 *   },
 * )
 */
class ContentModerationState extends ProcessorPluginBase {

  /**
   * Moderation information.
   *
   * @var \Drupal\content_moderation\ModerationInformationInterface
   */
  protected $moderationInformation;

  /**
   * The entity type manager service.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * Module handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $plugin = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $plugin->setEntityTypeManager($container->get('entity_type.manager'));
    $plugin->setModuleHandler($container->get('module_handler'));
    $plugin->setModerationInformation($container);

    return $plugin;
  }

  /**
   * Helper function to check content_moderation is enabled.
   */
  public function isHidden() {
    if ($this->moduleHandler->moduleExists('content_moderation')) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Stores Moderation information in protected property.
   *
   * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
   *   Moderation information.
   */
  protected function setModerationInformation(ContainerInterface $container) {
    if ($this->moduleHandler->moduleExists('content_moderation')) {
      $this->moderationInformation = $container->get('content_moderation.moderation_information');
    }
  }

  /**
   * Sets the entity type manager service.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager service.
   */
  public function setEntityTypeManager(EntityTypeManagerInterface $entity_type_manager) {
    $this->entityTypeManager = $entity_type_manager;
  }

  /**
   * Set the module handler service.
   *
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler service.
   */
  protected function setModuleHandler(ModuleHandlerInterface $moduleHandler) {
    $this->moduleHandler = $moduleHandler;
  }

  /**
   * {@inheritdoc}
   */
  public function getPropertyDefinitions(?DatasourceInterface $datasource = NULL) {
    $properties = [];
    if (!($datasource instanceof ContentEntity)) {
      return $properties;
    }
    $entity_type = $this->entityTypeManager->getDefinition($datasource->getEntityTypeId());

    if ($this->moderationInformation->isModeratedEntityType($entity_type)) {
      $definition = [
        'label' => $this->t('Content moderation state'),
        'description' => "Moderation state of current node revision.",
        'type' => 'string',
        'processor_id' => $this->getPluginId(),
      ];
      $properties['content_moderation_state'] = new ProcessorProperty($definition);
    }

    return $properties;
  }

  /**
   * {@inheritdoc}
   */
  public function addFieldValues(ItemInterface $item) {
    $object = $item->getOriginalObject();
    if (!($object instanceof ComplexDataInterface)) {
      return;
    }
    $entity = $object->getEntity();
    $fields = $this->getFieldsHelper()
      ->filterForPropertyPath($item->getFields(), 'entity:' . $entity->getEntityTypeId(), 'content_moderation_state');
    if (empty($fields)) {
      $fields = $this->getFieldsHelper()
        ->filterForPropertyPath($item->getFields(), 'entity_revision:' . $entity->getEntityTypeId(), 'content_moderation_state');
    }

    /** @var \Drupal\content_moderation\Plugin\Field\ModerationStateFieldItemList $moderation_state */
    $moderation_state = $object->get('moderation_state');
    $datasourceIds = [
      'entity:' . $entity->getEntityTypeId(),
      'entity_revision:' . $entity->getEntityTypeId(),
    ];
    foreach ($fields as $field) {
      if (in_array($field->getDatasourceId(), $datasourceIds)) {
        $field->addValue($moderation_state->get(0)->getValue()['value']);
      }
    }
  }

  /**
   * Calculate dependencies method.
   *
   * @return array
   *   Dependencies as array.
   */
  public function calculateDependencies() {
    parent::calculateDependencies();
    $this->addDependency('module', 'content_moderation');
    return $this->dependencies;
  }

}
