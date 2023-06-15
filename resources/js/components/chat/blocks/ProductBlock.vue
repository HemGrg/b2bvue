<template>
  <div v-if="product" class="block product-block">
    <div>
      <div class="border-bottom mb-2">Product Information</div>
      <div class="form-row">
        <div class="col-4">
          <img :src="product.image_url" class="img-fluid rounded bg-white" />
        </div>
        <div class="col-8">
          <a :href="`/products/${product.slug}`" target="_blank">{{ product.title }}</a>
          <div class="product__price__range">{{ product.price_range }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  props: ["message"],

  computed: {
    product()
    {
      return this.message.product;
    }
  }
};
</script>

<style scoped>
.message .product-block {
  padding: 15px;
  border-radius: 1rem;
}
.message.outgoing .product-block {
  background-color: #f5f5f5;
  color: #333;
}
.message.incomming .product-block {
  background-color: #2196f3;
  color: #fefefe;
}
</style>