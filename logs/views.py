from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from django.db.models import Count
from .models import CloudLog, NIDSLog
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.conf import settings
from django.http import HttpResponse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Load your encryption key and salt from files
def load_key_and_salt():
    key_path = os.path.join(settings.BASE_DIR, 'encryption_key.key')
    salt_path = os.path.join(settings.BASE_DIR, 'salt.salt')

    if not os.path.exists(key_path) or not os.path.exists(salt_path):
        raise FileNotFoundError("Key or salt file not found.")

    with open(key_path, 'rb') as key_file:
        key = key_file.read()
    with open(salt_path, 'rb') as salt_file:
        salt = salt_file.read()
    return key, salt

ENCRYPTION_KEY, SALT = load_key_and_salt()

def encrypt_file(input_file_path, output_file_path):
    backend = default_backend()
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()

    with open(input_file_path, 'rb') as f:
        plaintext = f.read()

    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file_path, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file(input_file_path, output_file_path):
    backend = default_backend()

    with open(input_file_path, 'rb') as f:
        iv = f.read(16)  # Extract the IV from the beginning
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file_path, 'wb') as f:
        f.write(plaintext)

def home(request):
    recent_nids_logs = NIDSLog.objects.filter(logged_at__gte=timezone.now() - timezone.timedelta(days=7)).order_by('-logged_at')
    recent_cloud_logs = CloudLog.objects.order_by('-timestamp')[:5]

    nids_log_data = NIDSLog.objects.filter(logged_at__gte=timezone.now() - timezone.timedelta(days=30)) \
        .annotate(date=TruncDate('logged_at')).values('date').annotate(count=Count('id')).order_by('date')

    nids_log_dates = [entry['date'].strftime('%Y-%m-%d') for entry in nids_log_data]
    nids_log_counts = [entry['count'] for entry in nids_log_data]

    return render(request, 'home.html', {
        'recent_nids_logs': recent_nids_logs,
        'recent_cloud_logs': recent_cloud_logs,
        'nids_log_dates': nids_log_dates,
        'nids_log_counts': nids_log_counts,
        'year': timezone.now().year
    })

def cloud_functionality(request):
    cloud_logs = CloudLog.objects.filter(is_deleted=False)  # Only show active files
    print(f"Available files: {[log.file_name for log in cloud_logs]}")
    return render(request, 'cloud_functionality.html', {'cloud_logs': cloud_logs})

def cloud_logs_view(request):
    logs = CloudLog.objects.all()  # Show all logs, including deleted ones
    return render(request, 'cloud_logs.html', {'logs': logs})

def upload_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        fs = FileSystemStorage()
        filename = fs.save(uploaded_file.name, uploaded_file)
        file_path = os.path.join(settings.MEDIA_ROOT, filename)  # Use correct path format

        # Encrypt the file before saving
        encrypted_file_path = file_path + '.enc'
        encrypt_file(file_path, encrypted_file_path)
        os.remove(file_path)  # Remove the unencrypted file

        print(f"File uploaded and encrypted at: {encrypted_file_path}")  # Debugging line
        CloudLog.objects.create(file_name=filename + '.enc', file_path=encrypted_file_path, activity=f"Uploaded {filename}")
        return redirect('cloud_functionality')
    return redirect('cloud_functionality')

def download_file(request, file_id):
    cloud_log = get_object_or_404(CloudLog, id=file_id)
    file_name = cloud_log.file_name
    encrypted_file_path = os.path.join(settings.MEDIA_ROOT, file_name)  # Build the full path
    decrypted_file_path = encrypted_file_path.replace('.enc', '')

    # Check if the file exists before attempting to open
    if not os.path.exists(encrypted_file_path):
        return HttpResponse("File not found.", status=404)

    # Decrypt the file before sending
    decrypt_file(encrypted_file_path, decrypted_file_path)

    with open(decrypted_file_path, 'rb') as file:
        response = HttpResponse(file.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{file_name.replace(".enc", "")}"'
    
    os.remove(decrypted_file_path)  # Remove the decrypted file after sending
    return response

def nids_logs(request):
    recent_nids_logs = NIDSLog.objects.all()
    return render(request, 'nids_logs.html', {'nids_logs': recent_nids_logs})

def cloud_logs(request):
    logs = CloudLog.objects.all()
    return render(request, 'cloud_logs.html', {'logs': logs})

def delete_file(request, file_id):
    log_entry = get_object_or_404(CloudLog, id=file_id)
    file_name = log_entry.file_name
    file_path = os.path.join(settings.MEDIA_ROOT, file_name)
    print(f"Attempting to delete file at: {file_path}")

    if os.path.exists(file_path):
        try:
            os.remove(file_path)  # Remove the file from the filesystem
            log_entry.delete()  # Mark the log entry as deleted
            print(f"Successfully marked file as deleted: {file_path}")
        except Exception as e:
            print(f"Error deleting file: {e}")
    else:
        print("File not found.")

    return redirect('cloud_functionality')
