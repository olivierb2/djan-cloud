from rest_framework import serializers
from .models import User, Folder, File, SharedFolder, SharedFolderMembership
import os


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'role', 'is_active']


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'role']

    def create(self, validated_data):
        email = validated_data.get('email', '')
        validated_data.setdefault('username', email.split('@')[0])
        return User.objects.create_user(**validated_data)


class FolderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Folder
        fields = ['id', 'name', 'full_path', 'parent', 'created_at', 'updated_at']


class FileSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()
    size = serializers.SerializerMethodField()

    class Meta:
        model = File
        fields = ['id', 'full_path', 'content_type', 'display_name', 'size', 'created_at', 'updated_at']

    def get_display_name(self, obj):
        return os.path.basename(obj.file.name) if obj.file else ''

    def get_size(self, obj):
        try:
            return obj.file.size
        except Exception:
            return 0


class SharedFolderSerializer(serializers.ModelSerializer):
    class Meta:
        model = SharedFolder
        fields = ['id', 'name', 'created_at']


class SharedFolderMembershipSerializer(serializers.ModelSerializer):
    email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = SharedFolderMembership
        fields = ['user', 'email', 'permission', 'joined_at']
