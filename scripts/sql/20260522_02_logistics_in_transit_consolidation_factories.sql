-- 在途物流拼柜工厂：一条在途记录可关联多个拼柜工厂（主工厂仍存 logistics_in_transit.factory_id）

CREATE TABLE IF NOT EXISTS `logistics_in_transit_consolidation_factories` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `transit_id` int(10) UNSIGNED NOT NULL,
  `factory_id` int(10) UNSIGNED NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_transit_consolidation_factory` (`transit_id`,`factory_id`),
  KEY `idx_transit_id` (`transit_id`),
  KEY `idx_factory_id` (`factory_id`),
  CONSTRAINT `fk_transit_consolidation_transit` FOREIGN KEY (`transit_id`) REFERENCES `logistics_in_transit` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_transit_consolidation_factory` FOREIGN KEY (`factory_id`) REFERENCES `logistics_factories` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
