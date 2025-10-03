<?php

namespace Drupal\search_api_revisions\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * The settings form for search_api_revisions.
 */
class SearchApiRevisionsSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['search_api_revisions.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'search_api_revisions_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('search_api_revisions.settings');

    $form = [
      '#type' => 'details',
      '#title' => $this->t('Search api revisions settings'),
      '#open' => TRUE,
      '#tree' => TRUE,
    ];

    $form['queue'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Queue settings'),
    ];

    $form['queue']['items_update_queue'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Update revisions in queue'),
      '#default_value' => $config->get('queue')['items_update_queue'] ?? FALSE,
    ];
    $form['index_previous_revisions'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Index previous revisions on update'),
      '#description' => $this->t('When enabled, all previous revisions of an entity will be reindexed. This is useful when indexing things like the published or default revision status.'),
      '#default_value' => $config->get('index_previous_revisions') ?? FALSE,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $queue = $form_state->getValue('queue');

    $this->config('search_api_revisions.settings')
      ->set('queue', $queue)
      ->set('index_previous_revisions', $form_state->getValue('index_previous_revisions'))
      ->save();
    parent::submitForm($form, $form_state);
  }

}
