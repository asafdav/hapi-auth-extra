test:
	@node node_modules/mocha/bin/mocha

test-cov: lib-cov
	@AUTH_EXTRA_COV=1 node_modules/mocha/bin/mocha -R html-cov > coverage.html

lib-cov:
	@node node_modules/jscoverage/bin/jscoverage lib lib-cov

.PHONY: test test-cov
