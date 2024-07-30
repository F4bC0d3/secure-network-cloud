from django.core.management.base import BaseCommand
from logs.models import CloudLog

class Command(BaseCommand):
    help = 'Clear all entries from CloudLog'

    def handle(self, *args, **kwargs):
        CloudLog.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Successfully cleared all CloudLog entries.'))
