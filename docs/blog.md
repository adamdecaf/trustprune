---
layout: default
title: Blog
nav_order: 9
---

# Blog

{% for post in site.posts %}
- [{{ post.title }}]({{ post.url | relative_url }}) — {{ post.date | date: "%Y-%m-%d" }}
{% endfor %}

[← Home](index.md)
