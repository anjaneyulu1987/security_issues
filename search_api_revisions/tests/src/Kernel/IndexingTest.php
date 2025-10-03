<?php

declare(strict_types=1);

namespace Drupal\Tests\search_api_revisions\Kernel;

use Drupal\entity_test\Entity\EntityTestRev;
use Drupal\KernelTests\KernelTestBase;
use Drupal\search_api\Entity\Index;
use Drupal\search_api\Entity\Server;
use Drupal\search_api\IndexInterface;
use Drupal\search_api\ServerInterface;
use Drupal\search_api_revisions\Plugin\QueueWorker\SearchApiRevisionsQueue;
use Drupal\search_api_revisions\Plugin\search_api\datasource\ContentEntityRevisions;
use Drupal\Tests\search_api\Kernel\PostRequestIndexingTrait;

/**
 * Tests tracking and indexing with the entity_revision datasource.
 *
 * @group search_api_revisions
 */
class IndexingTest extends KernelTestBase {

  use PostRequestIndexingTrait;

  /**
   * A test server.
   */
  protected ServerInterface $server;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'search_api',
    'search_api_revisions',
    'search_api_test',
    'user',
    'system',
    'entity_test',
  ];

  /**
   * {@inheritdoc}
   */
  public function setUp(): void {
    parent::setUp();

    $this->installSchema('search_api', ['search_api_item']);
    $this->installEntitySchema('entity_test_rev');
    $this->installEntitySchema('search_api_task');
    $this->installConfig(['search_api', 'search_api_revisions']);

    // Create a test server.
    $this->server = Server::create([
      'name' => 'Test server',
      'id' => 'test',
      'status' => 1,
      'backend' => 'search_api_test',
    ]);
    $this->server->save();
  }

  /**
   * Tests indexing works as expected.
   */
  public function testIndexing(): void {
    $entity = EntityTestRev::create()->setName('Test entity');
    $entity->save();
    $entity2 = EntityTestRev::create()->setName('Test entity 2');
    $entity2->save();

    $index = $this->createIndex();
    $index->save();
    $tracker = $index->getTrackerInstance();

    $this->assertEquals(2, $tracker->getTotalItemsCount());
    $this->assertEquals(0, $tracker->getIndexedItemsCount());

    $entity->save();
    $this->triggerPostRequestIndexing();

    // Index should have indexed the entity's revision.
    $this->assertEquals(2, $tracker->getTotalItemsCount());
    $this->assertEquals(1, $tracker->getIndexedItemsCount());

    // Create a bunch more revisions for both entities.
    $revCount1 = rand(3, 10);
    $revCount2 = rand(3, 10);
    $this->createRevisions($entity, $revCount1);
    $this->createRevisions($entity2, $revCount2);
    $queue = \Drupal::queue(SearchApiRevisionsQueue::PLUGIN_ID);
    $this->assertEquals(0, $queue->numberOfItems());

    // We should have the number of revisions of both entities + the first
    // 2 revisions indexed.
    $expectedCount = $revCount1 + $revCount2 + 2;
    $this->assertEquals($expectedCount, $tracker->getRemainingItemsCount());

    $this->triggerPostRequestIndexing();
    $this->assertEquals($expectedCount, $tracker->getTotalItemsCount());
    $this->assertEquals($expectedCount, $tracker->getIndexedItemsCount());
    $this->assertEquals(0, $tracker->getRemainingItemsCount());

    // Enable queueing for reindexing previous revisions.
    \Drupal::configFactory()->getEditable('search_api_revisions.settings')->set('queue.items_update_queue', TRUE)->save();
    $this->assertEquals(0, $queue->numberOfItems());

    $revIdToDelete = $entity->getRevisionId();
    $this->createRevisions($entity, 5);
    // Only the 5 new revisions should be remaining to be tracked.
    $this->assertEquals(5, $tracker->getRemainingItemsCount());
    // Queue should contain 1 item per new revision.
    $this->assertEquals(5, $queue->numberOfItems());

    // Process a single queue item, this will mark all revisions for an entity
    // as updated. We have 1 initial revision, $revCount1 randomly added revs
    // then 5 new ones.
    $this->processQueueItem();
    $this->assertEquals($revCount1 + 1 + 5, $tracker->getRemainingItemsCount());

    $expectedCount = $expectedCount + 5;
    $this->assertEquals($expectedCount, $tracker->getTotalItemsCount());
    // Deleting a revision should only remove that revision.
    /** @var \Drupal\Core\Entity\RevisionableStorageInterface $storage */
    $storage = \Drupal::entityTypeManager()->getStorage($entity->getEntityTypeId());
    $storage->deleteRevision($revIdToDelete);
    $expectedCount = $expectedCount - 1;
    $this->assertEquals($expectedCount, $tracker->getTotalItemsCount());

    // Deleting the whole entity should remove all revisions.
    $entity->delete();
    // Only revisions from $entity2 remain.
    $this->assertEquals($revCount2 + 1, $tracker->getTotalItemsCount());
  }

  /**
   * Tests indexing with index_previous_revisions turned off.
   */
  public function testIndexingNoPreviousRevisions(): void {
    $index = $this->createIndex();
    $index->save();
    $tracker = $index->getTrackerInstance();

    $entity = EntityTestRev::create()->setName('Test entity');
    $entity->save();

    $this->createRevisions($entity, 3);

    $this->assertEquals(4, $tracker->getTotalItemsCount());
    $this->assertEquals(4, $tracker->getRemainingItemsCount());
    $this->triggerPostRequestIndexing();
    $this->assertEquals(4, $tracker->getTotalItemsCount());
    $this->assertEquals(0, $tracker->getRemainingItemsCount());

    \Drupal::configFactory()->getEditable('search_api_revisions.settings')->set('index_previous_revisions', FALSE)->save();

    $this->createRevisions($entity, 5);

    // Only the new revisions should be marked for indexing.
    $this->assertEquals(5, $tracker->getRemainingItemsCount());
    $this->triggerPostRequestIndexing();
    $this->assertEquals(9, $tracker->getTotalItemsCount());
    $this->assertEquals(0, $tracker->getRemainingItemsCount());
  }

  /**
   * Create a number of revisions for an entity.
   */
  private function createRevisions(EntityTestRev $entity, int $count): void {
    $i = 0;
    while ($i < $count) {
      $entity->setNewRevision(TRUE);
      $entity->setName($this->randomMachineName())->save();
      $i++;
    }
  }

  /**
   * Processes a queue item.
   */
  private function processQueueItem(): void {
    $queue = \Drupal::queue(SearchApiRevisionsQueue::PLUGIN_ID);
    $item = $queue->claimItem();
    $worker = \Drupal::service('plugin.manager.queue_worker')->createInstance(SearchApiRevisionsQueue::PLUGIN_ID);
    $worker->processItem($item->data);
  }

  /**
   * Creates a test index.
   */
  protected function createIndex(): IndexInterface {
    return Index::create([
      'name' => $this->getRandomGenerator()->string(),
      'id' => $this->getRandomGenerator()->name(),
      'status' => 1,
      'datasource_settings' => [
        ContentEntityRevisions::PLUGIN_ID . ':entity_test_rev' => [],
      ],
      'tracker_settings' => [
        'default' => [],
      ],
      'server' => $this->server->id(),
      'options' => ['index_directly' => TRUE],
    ]);
  }

}
