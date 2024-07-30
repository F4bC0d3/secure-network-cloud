# logs/migrations/0005_update_file_paths.py
from django.db import migrations, models

def update_file_paths(apps, schema_editor):
    CloudLog = apps.get_model('logs', 'CloudLog')
    for log in CloudLog.objects.all():
        log.file_path = 'path/to/existing/files/' + log.file_name  # Adjust the path as needed
        log.save()

class Migration(migrations.Migration):

    dependencies = [
        ('logs', '0005_temp_break_cycle'),
    ]

    operations = [
        migrations.AddField(
            model_name='cloudlog',
            name='file_path',
            field=models.CharField(max_length=255, default='default/path'),
            preserve_default=False,
        ),
        migrations.RunPython(update_file_paths),
    ]
