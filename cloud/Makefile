# Packaging helpers for the AWS deployment.
LAYER_DIR := terraform/.build/layer
LAYER_ZIP := terraform/.build/spacelab-layer.zip

.PHONY: layer clean

layer: ## Package src/spacelab as a Lambda layer
	rm -rf $(LAYER_DIR) && mkdir -p $(LAYER_DIR)/python
	cp -r ../src/spacelab $(LAYER_DIR)/python/
	find $(LAYER_DIR) -name '__pycache__' -type d -prune -exec rm -rf {} +
	cd $(LAYER_DIR) && zip -qr ../../../$(LAYER_ZIP) python
	@echo "built $(LAYER_ZIP)"

clean:
	rm -rf terraform/.build
