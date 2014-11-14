test-cov: clean lib-cov
	@HAPI_AUTHORIZATION_COV=1 node_modules/mocha/bin/mocha -R html-cov > coverage.html

clean:
	@rm -rf ./lib-cov \
	@rm -f coverage.html

lib-cov:
	@node node_modules/jscoverage/bin/jscoverage lib lib-cov

.PHONY: test test-cov
