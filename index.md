---
layout: post
title: tree's blog
---
{% for post in site.posts %}
{% increment index %}. {{post.date | date: "%b %d, %Y"}} - [{{post.title}}]({{post.url}})
{% endfor %}