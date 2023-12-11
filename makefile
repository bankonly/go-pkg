git.publish:
	git add .
	git commit -m "$v"
	git tag v$v
	git push origin v$v