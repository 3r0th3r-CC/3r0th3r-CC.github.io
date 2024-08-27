# 3r0th3r CC Blog

![readme](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/web/readme.png)

:book: Theme Docs: [English](https://butterfly.js.org/en/posts/butterfly-docs-en-get-started/)

## :closed_book: Latest Blog Posts

<!-- Fetch-Blog-Post:Start -->
- [Digital Dragon CTF 2024 Writeup](https://3r0th3r-cc.github.io/2024/08/25/Digital-Dragon-CTF-2024-Writeup/)
<!-- Fetch-Blog-Post:End -->

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

First, let's create a new branch **(Please do not write directly on the master branch)**:

```sh
git checkout -b <new_branch_name>
```

Now you can create a new post and write your stuff:

```sh
hexo new <new_post_name>
```

> The new post will be located at `/source/_posts`

> You should save your images, videos or scripts at `/source/assets`. For example: `/source/assets/images/posts/testctf-writeup/a.png`

If you want to see how your post looks like on blog, just need to run this following command:

```sh
hexo s
```

or this:

```sh
hexo server
```

Then visit `http://localhost:4000` to view that post!

## :newspaper: Publish

Run this command to add all changes and create commit

```sh
git add -A && git commit -m "<commit_name>"
```

Then push it to [our repository](https://github.com/3r0th3r-CC/3r0th3r-CC.github.io)

```sh
git push --set-upstream origin <your_branch_name>
```

or this if you pushed it before

```sh
git push
```


**This is an important part**

1. On [our repository](https://github.com/3r0th3r-CC/3r0th3r-CC.github.io), click on **Pull Requests**

2. Next, click on **New pull request** and select the branch you want to merge with the **master** branch

3. After creating the pull request, if there are no conflicts, merge your branch with the **master** branch and then delete it

> In case any conflict arises, ask the **admin** and he will definitely resolve it for you :)

## :recycle: Update

Check out the **master** branch first:

```sh
git checkout master
```

Then `fetch` and `pull` all changes from the remote repository:

```sh
git fetch && git pull
```
