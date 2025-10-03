<?php

namespace Drupal\search_api_revisions\Plugin\search_api\processor;

use Drupal\Core\Entity\RevisionableInterface;
use Drupal\Core\TypedData\ComplexDataInterface;
use Drupal\search_api\Datasource\DatasourceInterface;
use Drupal\search_api\Item\ItemInterface;
use Drupal\search_api\Processor\ProcessorPluginBase;
use Drupal\search_api\Processor\ProcessorProperty;
use Drupal\search_api_revisions\Plugin\search_api\datasource\ContentEntityRevisions;

/**
 * Adds an additional field containing is_last_revision.
 *
 * @SearchApiProcessor(
 *   id = "is_last_revision",
 *   label = @Translation("Revision is last"),
 *   description = @Translation("Checks whether saved revision is last."),
 *   stages = {
 *   "add_properties" = 0,
 *     "pre_index_save" = -10,
 *     "preprocess_index" = -30
 *   },
 * )
 */
class IsLastRevision extends ProcessorPluginBase {

  /**
   * {@inheritdoc}
   */
  public function getPropertyDefinitions(?DatasourceInterface $datasource = NULL) {
    $properties = [];
    if (!($datasource instanceof ContentEntityRevisions)) {
      return $properties;
    }
    $definition = [
      'label' => $this->t('Is last revision?'),
      'description' => $this->t('Whether this revision is last or not.'),
      'type' => 'boolean',
      'processor_id' => $this->getPluginId(),
    ];
    $properties['is_last_revision'] = new ProcessorProperty($definition);
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
    /** @var \Drupal\Core\Entity\RevisionableContentEntityBase $entity */
    $entity = $object->getValue();
    if (!$entity instanceof RevisionableInterface) {
      return;
    }

    $datasource_id = ContentEntityRevisions::getDatasourceIdForEntity($entity);
    $fields = $this->getFieldsHelper()
      ->filterForPropertyPath($item->getFields(), $datasource_id, 'is_last_revision');
    foreach ($fields as $field) {
      if ($field->getDatasourceId() == $datasource_id) {
        $field->addValue($entity->isLatestRevision());
      }
    }
  }

}
