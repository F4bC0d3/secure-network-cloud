# Generated by Django 5.0.7 on 2024-07-17 11:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('logs', '0010_remove_cloudlog_uploaded_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='cloudlog',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
    ]