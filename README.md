# 3r0th3r CC Blog

![readme](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/web/readme.png)

:book: Theme Docs: [English](https://butterfly.js.org/en/posts/butterfly-docs-en-get-started/)

## :computer: Installation

### GIT

**HTTPS**

```
git clone -b master https://github.com/3r0th3r-CC/3r0th3r-cc.github.io.git
```

or

**SSH**

```
git clone -b master git@github.com:3r0th3r-CC/3r0th3r-cc.github.io.git
```

### NPM

After cloning the repo, `cd` into that repo and run the following command:

```sh
npm i hexo && sudo npm install hexo-cli -g
```

## :writing_hand: Writing

First, let's create a new branch:

```sh
git checkout -b <new_branch_name>
```

Now you can create a new post and write your stuff:

```sh
hexo new <new_post_name>
```

> The new post will be located at `/source/_posts`

If you want to see how your post looks like on blog, just need to run this following command:

```sh
hexo s
```

Then visit `http://localhost:4000` to view that post!

## :newspaper: Publish

Run this command to add all changes and create commit

```sh
git add && git commit -m "<commit_name>"
```

Then push it to [our repository](https://github.com/3r0th3r-CC/3r0th3r-CC.github.io)

```sh
git push
```

**This is an important part**

On [our repository](https://github.com/3r0th3r-CC/3r0th3r-CC.github.io), click **Pull Requests**

Then ask the admin for more, I'm lazy :)
