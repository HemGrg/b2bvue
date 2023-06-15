<?php

namespace Modules\Front\Http\Controllers;

use Illuminate\Routing\Controller;
use Modules\Blog\Entities\Blog;
use Modules\Blog\Transformers\BlogResource;

class BlogApiController extends Controller
{
    public function index()
    {
        $blogs = Blog::published()
            ->when(request()->filled('limit'), function ($query) {
                $query->limit(request('limit'));
            })
            ->latest()
            ->get();

        return BlogResource::collection($blogs)->hide([
            'description',
            'id'
        ]);
    }

    public function show(Blog $blog)
    {
        return new BlogResource($blog);
    }
}
