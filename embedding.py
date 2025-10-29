import ollama

from main import app, db
from models import Product


def update_embedding():
    # Loop through all products
    products = Product.query.all()

    for product in products:
        if product.embedding is not None:
            print(f"⏭️  Skipping {product.name} (already has embedding)")
            continue

        # Get the product name
        text = product.name

        # Generate the embedding from Ollama
        response = ollama.embeddings(
            model="nomic-embed-text:v1.5",
            prompt=text
        )

        # Extract the embedding vector
        embedding = response["embedding"]

        # Save it to the product record
        product.embedding = embedding

        # Commit THIS product before moving to the next
        db.session.commit()

        print(f"✅ Saved embedding for: {product.name}")


if __name__ == "__main__":
    with app.app_context():
        update_embedding()
