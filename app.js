// app.js

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
const port = process.env.PORT || 3000; // Sunucunun çalışacağı port

// Password hashing functions
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return salt + ':' + hash;
}

function verifyPassword(password, hashedPassword) {
    const [salt, hash] = hashedPassword.split(':');
    const verifyHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === verifyHash;
}

// Admin middleware
async function requireAdmin(req, res, next) {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.status(401).json({ message: 'Kullanıcı kimliği gerekli.' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }
        
        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Bu işlem için admin yetkisi gerekli.' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        console.error('Admin yetki kontrolü hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
}

// Middleware
app.use(cors({
    origin: ['https://mertdeveci94.github.io', 'http://localhost:3000', 'http://localhost:8000'],
    credentials: true
})); // CORS configuration for production
app.use(bodyParser.json()); // JSON istek gövdelerini ayrıştırmak için
app.use(bodyParser.urlencoded({ extended: true })); // URL-encoded form data için

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        // Generate unique filename with timestamp
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        // Check file type
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Sadece resim dosyaları yüklenebilir!'), false);
        }
    }
});

// MongoDB Bağlantısı
// Kendi MongoDB bağlantı dizginizi buraya ekleyin.
// Örneğin: 'mongodb://localhost:27017/dailyloop' veya bir MongoDB Atlas bağlantı dizgisi
const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://pixelbrickart:eYIy9vGRN7rpdJpL@clustermd.q15vyvx.mongodb.net/?retryWrites=true&w=majority&appName=ClusterMD';

mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB\'ye başarıyla bağlanıldı.'))
    .catch(err => console.error('MongoDB bağlantı hatası:', err));

// MongoDB Şeması ve Modelleri

// Users Şeması
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // Gerçek uygulamada hash'lenmiş olmalı
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    following: { type: Number, default: 0 },
    followers: { type: Number, default: 0 },
    posts: { type: Number, default: 0 },
    bio: { type: String, default: '' },
    avatar: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Posts Şeması
const postSchema = new mongoose.Schema({
    title: { type: String, required: true, maxlength: 100 }, // Gönderi başlığı
    author: { type: String, required: true }, // Gönderi sahibi (örneğin kullanıcı adı)
    authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Kullanıcı referansı
    content: { type: String, required: true }, // Gönderi içeriği/açıklaması
    sourceUrl: { type: String, default: null }, // Gerçek kaynak linki
    videoUrl: { type: String, default: null }, // Video URL'si (YouTube, Vimeo vs.)
    category: { type: String, default: null }, // Gönderi kategorisi
    imageUrl: { type: String, default: null }, // İsteğe bağlı görsel URL'si
    tags: { type: [String], default: [] }, // Etiketler dizisi
    likes: { type: Number, default: 0 }, // Beğenme sayısı
    comments: [{ // Yorumlar dizisi
        author: String,
        authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        content: String,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now } // Gönderi oluşturulma tarihi
});

const Post = mongoose.model('Post', postSchema);

// API Uç Noktaları

// Test endpoint
app.post('/api/test', (req, res) => {
    console.log('Test endpoint hit with body:', req.body);
    res.json({ message: 'Test başarılı', receivedData: req.body });
});

// Authentication Endpoints

// Kullanıcı Kaydı (POST /api/auth/register)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { firstName, lastName, username, email, password, name } = req.body;

        // firstName ve lastName varsa name'i oluştur, yoksa eski name'i kullan
        const fullName = (firstName && lastName) ? `${firstName} ${lastName}` : name;

        // Basit doğrulama
        if ((!firstName || !lastName) && !name) {
            return res.status(400).json({ message: 'Ad ve soyad veya tam ad zorunludur.' });
        }
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Tüm alanlar zorunludur.' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Şifre en az 6 karakter olmalıdır.' });
        }

        // E-posta ve username kontrolü
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });
        if (existingUser) {
            if (existingUser.email === email) {
                return res.status(400).json({ message: 'Bu e-posta adresi zaten kullanılıyor.' });
            } else {
                return res.status(400).json({ message: 'Bu kullanıcı adı zaten kullanılıyor.' });
            }
        }

        // Şifreyi hash'le
        const hashedPassword = hashPassword(password);

        // Yeni kullanıcı oluştur
        const newUser = new User({
            name: fullName,
            firstName: firstName || fullName.split(' ')[0],
            lastName: lastName || (fullName.split(' ').length > 1 ? fullName.split(' ').slice(1).join(' ') : ''),
            username,
            email,
            password: hashedPassword
        });

        await newUser.save();

        // Şifreyi response'dan çıkar
        const userResponse = {
            id: newUser._id,
            name: newUser.name,
            firstName: newUser.firstName,
            lastName: newUser.lastName,
            username: newUser.username,
            email: newUser.email,
            role: newUser.role,
            following: newUser.following,
            followers: newUser.followers,
            posts: newUser.posts,
            bio: newUser.bio,
            avatar: newUser.avatar,
            createdAt: newUser.createdAt
        };

        res.status(201).json({
            message: 'Kullanıcı başarıyla oluşturuldu.',
            user: userResponse
        });

    } catch (error) {
        console.error('Kullanıcı kaydı hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// Kullanıcı Girişi (POST /api/auth/login)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Basit doğrulama
        if (!email || !password) {
            return res.status(400).json({ message: 'E-posta ve şifre zorunludur.' });
        }

        // Kullanıcıyı bul
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Geçersiz e-posta veya şifre.' });
        }

        // Şifre kontrolü
        if (!verifyPassword(password, user.password)) {
            return res.status(401).json({ message: 'Geçersiz e-posta veya şifre.' });
        }

        // Şifreyi response'dan çıkar
        const userResponse = {
            id: user._id,
            name: user.name,
            firstName: user.firstName,
            lastName: user.lastName,
            username: user.username,
            email: user.email,
            role: user.role,
            following: user.following,
            followers: user.followers,
            posts: user.posts,
            bio: user.bio,
            avatar: user.avatar,
            createdAt: user.createdAt
        };

        res.status(200).json({
            message: 'Başarıyla giriş yapıldı.',
            user: userResponse
        });

    } catch (error) {
        console.error('Kullanıcı girişi hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// Kullanıcı Profili Güncelleme (PUT /api/auth/profile/:id)
app.put('/api/auth/profile/:id', async (req, res) => {
    try {
        const { firstName, lastName, bio, name } = req.body;
        const userId = req.params.id;

        // firstName ve lastName varsa name'i oluştur, yoksa eski name'i kullan
        const updateData = { bio };
        if (firstName && lastName) {
            updateData.name = `${firstName} ${lastName}`;
            updateData.firstName = firstName;
            updateData.lastName = lastName;
        } else if (name) {
            updateData.name = name;
            updateData.firstName = name.split(' ')[0];
            updateData.lastName = name.split(' ').length > 1 ? name.split(' ').slice(1).join(' ') : '';
        }

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            updateData,
            { new: true, runValidators: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }

        // Şifreyi response'dan çıkar
        const userResponse = {
            id: updatedUser._id,
            name: updatedUser.name,
            firstName: updatedUser.firstName,
            lastName: updatedUser.lastName,
            username: updatedUser.username,
            email: updatedUser.email,
            role: updatedUser.role,
            following: updatedUser.following,
            followers: updatedUser.followers,
            posts: updatedUser.posts,
            bio: updatedUser.bio,
            avatar: updatedUser.avatar,
            createdAt: updatedUser.createdAt
        };

        res.status(200).json(userResponse);

    } catch (error) {
        console.error('Profil güncelleme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// 1. Yeni Gönderi Oluşturma (POST /api/posts)
app.post('/api/posts', upload.single('image'), async (req, res) => {
    try {
        console.log('Post creation request received:', req.body);
        console.log('File received:', req.file);
        
        const { title, author, content, category, tags, sourceUrl, videoUrl, postUrl } = req.body;
        
        // postUrl field'ını hem sourceUrl hem de videoUrl için kullan
        const finalSourceUrl = postUrl || sourceUrl;
        const finalVideoUrl = postUrl && (postUrl.includes('youtube.com') || postUrl.includes('youtu.be') || postUrl.includes('vimeo.com')) ? postUrl : videoUrl;

        // Basit bir doğrulama
        if (!title || !author || !content) {
            console.log('Validation failed: missing required fields');
            return res.status(400).json({ message: 'Başlık, yazar ve içerik alanları zorunludur.' });
        }

        // Process tags if provided
        let processedTags = [];
        if (tags) {
            if (typeof tags === 'string') {
                processedTags = tags.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
            } else if (Array.isArray(tags)) {
                processedTags = tags;
            }
        }

        // Handle uploaded image
        let imageUrl = null;
        if (req.file) {
            imageUrl = '/uploads/' + req.file.filename;
        }

        console.log('Creating post with data:', {
            title,
            author,
            content,
            category: category || null,
            sourceUrl: sourceUrl || null,
            videoUrl: videoUrl || null,
            imageUrl: imageUrl,
            tags: processedTags
        });

        const newPost = new Post({
            title,
            author,
            content,
            category: category || null,
            sourceUrl: finalSourceUrl || null,
            videoUrl: finalVideoUrl || null,
            imageUrl: imageUrl,
            tags: processedTags
        });

        console.log('Saving post...');
        const savedPost = await newPost.save();
        console.log('Post saved successfully:', savedPost._id);
        
        res.status(201).json(savedPost); // Başarıyla oluşturuldu (201 Created)
    } catch (error) {
        console.error('Gönderi oluşturma hatası:', error);
        console.error('Error details:', error.message);
        console.error('Error stack:', error.stack);
        console.error('Request body:', req.body);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// 2. Tüm Gönderileri Getirme (GET /api/posts)
app.get('/api/posts', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const category = req.query.category;
        const author = req.query.author;
        
        console.log(`Loading posts - Page: ${page}, Limit: ${limit}, Skip: ${skip}, Category: ${category}, Author: ${author}`);
        
        // Build query filter
        let filter = {};
        if (category && category.trim() !== '') {
            filter.category = category;
        }
        if (author && author.trim() !== '') {
            filter.author = author;
        }
        
        // En yeni gönderileri en üste getirmek için createdAt'e göre azalan sıralama
        const posts = await Post.find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);
            
        const totalPosts = await Post.countDocuments(filter);
        const hasMore = skip + posts.length < totalPosts;
        
        console.log(`Found ${posts.length} posts, Total: ${totalPosts}, Has more: ${hasMore}`);
        
        res.status(200).json({
            posts,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(totalPosts / limit),
                totalPosts,
                hasMore
            }
        });
    } catch (error) {
        console.error('Gönderileri getirme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası, gönderiler alınamadı.' });
    }
});

// 3. Tek Bir Gönderiyi Getirme (GET /api/posts/:id) - İsteğe bağlı
app.get('/api/posts/:id', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(404).json({ message: 'Gönderi bulunamadı.' });
        }
        res.status(200).json(post);
    } catch (error) {
        console.error('Tek gönderi getirme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 4. Gönderiyi Güncelleme (PUT /api/posts/:id) - İsteğe bağlı
app.put('/api/posts/:id', upload.single('image'), async (req, res) => {
    try {
        console.log('PUT /api/posts/:id received:', req.body);
        console.log('PUT /api/posts/:id file:', req.file);
        const { title, content, category, sourceUrl, videoUrl, postUrl, imageUrl, tags } = req.body;
        
        // postUrl field'ını hem sourceUrl hem de videoUrl için kullan
        const finalSourceUrl = postUrl || sourceUrl;
        const finalVideoUrl = postUrl && (postUrl.includes('youtube.com') || postUrl.includes('youtu.be') || postUrl.includes('vimeo.com')) ? postUrl : videoUrl;
        
        // Tags processing - convert string to array if needed
        let processedTags = [];
        if (tags) {
            if (typeof tags === 'string') {
                processedTags = tags.split(',').map(tag => tag.trim()).filter(tag => tag);
            } else if (Array.isArray(tags)) {
                processedTags = tags;
            }
        }
        
        const updateData = {
            title,
            content,
            category,
            sourceUrl: finalSourceUrl,
            videoUrl: finalVideoUrl,
            tags: processedTags
        };
        
        // Handle image upload - new image takes priority, then remove option, then keep existing
        if (req.file) {
            updateData.imageUrl = '/uploads/' + req.file.filename;
            console.log('New image uploaded:', updateData.imageUrl);
        } else if (req.body.removeImage === 'on' || req.body.removeImage === 'true') {
            updateData.imageUrl = null;
            console.log('Current image removed');
        } else if (imageUrl !== undefined) {
            updateData.imageUrl = imageUrl;
        }
        
        const updatedPost = await Post.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true } // Güncellenmiş belgeyi döndür ve şema doğrulamayı çalıştır
        );

        if (!updatedPost) {
            return res.status(404).json({ message: 'Gönderi bulunamadı.' });
        }
        
        console.log('Post updated successfully:', updatedPost.title);
        res.status(200).json(updatedPost);
    } catch (error) {
        console.error('Gönderi güncelleme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// 5. Gönderiyi Silme (DELETE /api/posts/:id) - İsteğe bağlı
app.delete('/api/posts/:id', async (req, res) => {
    try {
        const deletedPost = await Post.findByIdAndDelete(req.params.id);

        if (!deletedPost) {
            return res.status(404).json({ message: 'Gönderi bulunamadı.' });
        }
        res.status(200).json({ message: 'Gönderi başarıyla silindi.' });
    } catch (error) {
        console.error('Gönderi silme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 5a. Admin Gönderi Silme (DELETE /api/admin/posts/:id)
app.delete('/api/admin/posts/:id', requireAdmin, async (req, res) => {
    try {
        const postId = req.params.id;
        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ message: 'Gönderi bulunamadı.' });
        }

        await Post.findByIdAndDelete(postId);
        
        console.log(`🗑️ Admin ${req.user.username} deleted post: ${post.title}`);
        
        res.status(200).json({ 
            message: 'Gönderi admin tarafından silindi.',
            deletedPost: {
                id: post._id,
                title: post.title,
                author: post.author
            }
        });
    } catch (error) {
        console.error('Admin gönderi silme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 5b. Admin Gönderi Güncelleme (PUT /api/admin/posts/:id)
app.put('/api/admin/posts/:id', upload.single('image'), requireAdmin, async (req, res) => {
    try {
        const postId = req.params.id;
        console.log('Admin PUT received:', req.body);
        console.log('Admin PUT file:', req.file);
        const { title, content, category, sourceUrl, videoUrl, imageUrl } = req.body;
        
        const updateData = {
            title, 
            content, 
            category, 
            sourceUrl, 
            videoUrl
        };
        
        // Handle image upload - new image takes priority, then remove option, then keep existing
        if (req.file) {
            updateData.imageUrl = '/uploads/' + req.file.filename;
            console.log('Admin: New image uploaded:', updateData.imageUrl);
        } else if (req.body.removeImage === 'on' || req.body.removeImage === 'true') {
            updateData.imageUrl = null;
            console.log('Admin: Current image removed');
        } else if (imageUrl !== undefined) {
            updateData.imageUrl = imageUrl;
        }
        
        const updatedPost = await Post.findByIdAndUpdate(
            postId,
            updateData,
            { new: true, runValidators: true }
        );

        if (!updatedPost) {
            return res.status(404).json({ message: 'Gönderi bulunamadı.' });
        }
        
        console.log(`✏️ Admin ${req.user.username} updated post: ${updatedPost.title}`);
        
        res.status(200).json({
            message: 'Gönderi admin tarafından güncellendi.',
            post: updatedPost
        });
    } catch (error) {
        console.error('Admin gönderi güncelleme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 6. Gönderi Beğenme/Beğenmeme (POST /api/posts/:id/like)
app.post('/api/posts/:id/like', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        
        if (!post) {
            return res.status(404).json({ message: 'Gönderi bulunamadı.' });
        }
        
        // Beğeni sayısını artır
        post.likes += 1;
        await post.save();
        
        res.status(200).json({ likes: post.likes, message: 'Gönderi beğenildi.' });
    } catch (error) {
        console.error('Gönderi beğenme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 7. Kullanıcı Profili Getirme (GET /api/user/profile)
app.get('/api/user/profile', async (req, res) => {
    try {
        // Demo kullanıcı bilgileri - Gerçek uygulamada authentication gerekir
        const userProfile = {
            id: 'user123',
            name: 'Ceren Deveci',
            email: 'ceren@example.com',
            following: 42,
            followers: 156,
            posts: 23,
            avatar: null,
            bio: 'Frontend Developer',
            createdAt: new Date('2023-01-01')
        };
        
        res.status(200).json(userProfile);
    } catch (error) {
        console.error('Kullanıcı profili getirme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 8. Bildirimler Getirme (GET /api/notifications)
app.get('/api/notifications', async (req, res) => {
    try {
        // Demo bildirimler - Gerçek uygulamada veritabanından gelir
        const notifications = [
            {
                id: 'notif1',
                author: 'Ahmet Yılmaz',
                message: 'Gönderinizi beğendi',
                type: 'like',
                createdAt: new Date(Date.now() - 1000 * 60 * 30), // 30 dakika önce
                read: false
            },
            {
                id: 'notif2',
                author: 'Elif Kaya',
                message: 'Gönderinize yorum yaptı',
                type: 'comment',
                createdAt: new Date(Date.now() - 1000 * 60 * 60 * 2), // 2 saat önce
                read: false
            },
            {
                id: 'notif3',
                author: 'Mehmet Özkan',
                message: 'Sizi takip etmeye başladı',
                type: 'follow',
                createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24), // 1 gün önce
                read: true
            }
        ];
        
        res.status(200).json(notifications);
    } catch (error) {
        console.error('Bildirimler getirme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 9. Kategoriler Getirme (GET /api/categories)
app.get('/api/categories', async (req, res) => {
    try {
        const categories = [
            { id: 1, name: 'Teknoloji', icon: 'fa-microchip', color: '#3B82F6' },
            { id: 2, name: 'Eğitim', icon: 'fa-graduation-cap', color: '#059669' },
            { id: 3, name: 'Kariyer', icon: 'fa-briefcase', color: '#EA580C' },
            { id: 4, name: 'Bilim', icon: 'fa-flask', color: '#DC2626' },
            { id: 5, name: 'Sanat & Tasarım', icon: 'fa-palette', color: '#7C3AED' },
            { id: 6, name: 'Yaşam', icon: 'fa-heart', color: '#EC4899' },
            { id: 7, name: 'Girişimcilik', icon: 'fa-rocket', color: '#F59E0B' },
            { id: 8, name: 'Seyahat', icon: 'fa-plane', color: '#0891B2' },
            { id: 9, name: 'Diğerleri', icon: 'fa-ellipsis-h', color: '#6B7280' }
        ];
        
        res.status(200).json(categories);
    } catch (error) {
        console.error('Kategoriler getirme hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 10. Arama (GET /api/search)
app.get('/api/search', async (req, res) => {
    try {
        const { q, category, limit = 10 } = req.query;
        
        if (!q) {
            return res.status(400).json({ message: 'Arama sorgusu gerekli.' });
        }
        
        let searchQuery = {
            $or: [
                { content: { $regex: q, $options: 'i' } },
                { author: { $regex: q, $options: 'i' } }
            ]
        };
        
        if (category) {
            searchQuery.category = category;
        }
        
        const posts = await Post.find(searchQuery)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));
            
        res.status(200).json(posts);
    } catch (error) {
        console.error('Arama hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});

// 11. URL Metadata Çekme (POST /api/url-metadata)
app.post('/api/url-metadata', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ message: 'URL gerekli.' });
        }
        
        // URL validation
        let validUrl;
        try {
            validUrl = new URL(url);
        } catch (error) {
            return res.status(400).json({ message: 'Geçersiz URL formatı.' });
        }
        
        // Fetch webpage content
        const response = await axios.get(url, {
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        });
        
        const html = response.data;
        const $ = cheerio.load(html);
        
        // Extract metadata
        const metadata = {
            title: null,
            description: null,
            image: null,
            url: url,
            domain: validUrl.hostname
        };
        
        // Try Open Graph first
        metadata.title = $('meta[property="og:title"]').attr('content') || 
                        $('meta[name="twitter:title"]').attr('content') ||
                        $('title').text().trim() || null;
                        
        metadata.description = $('meta[property="og:description"]').attr('content') ||
                              $('meta[name="twitter:description"]').attr('content') ||
                              $('meta[name="description"]').attr('content') || null;
                              
        metadata.image = $('meta[property="og:image"]').attr('content') ||
                        $('meta[name="twitter:image"]').attr('content') ||
                        $('meta[name="twitter:image:src"]').attr('content') || null;
        
        // Make image URL absolute if relative
        if (metadata.image && !metadata.image.startsWith('http')) {
            if (metadata.image.startsWith('//')) {
                metadata.image = validUrl.protocol + metadata.image;
            } else if (metadata.image.startsWith('/')) {
                metadata.image = validUrl.origin + metadata.image;
            } else {
                metadata.image = validUrl.origin + '/' + metadata.image;
            }
        }
        
        // Clean up data
        if (metadata.title) {
            metadata.title = metadata.title.substring(0, 200);
        }
        if (metadata.description) {
            metadata.description = metadata.description.substring(0, 500);
        }
        
        console.log('📄 URL metadata extracted:', {
            url: metadata.url,
            title: metadata.title ? metadata.title.substring(0, 50) + '...' : 'No title',
            hasImage: !!metadata.image
        });
        
        res.status(200).json(metadata);
        
    } catch (error) {
        console.error('URL metadata hatası:', error.message);
        
        if (error.code === 'ENOTFOUND') {
            return res.status(400).json({ message: 'URL\'ye ulaşılamadı.' });
        }
        if (error.code === 'ECONNABORTED') {
            return res.status(400).json({ message: 'URL zaman aşımına uğradı.' });
        }
        
        res.status(500).json({ message: 'Metadata çekilemedi.' });
    }
});

// Static files serve (for uploaded images)
app.use('/uploads', express.static('uploads'));

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Get all users (for users page) - Admin only
app.post('/api/users', requireAdmin, async (req, res) => {
    try {
        console.log('📋 Getting users list...');
        
        // Get users with post counts
        const users = await User.aggregate([
            {
                $lookup: {
                    from: 'posts',
                    localField: '_id',
                    foreignField: 'authorId',
                    as: 'posts'
                }
            },
            {
                $addFields: {
                    postsCount: { $size: '$posts' }
                }
            },
            {
                $project: {
                    password: 0,
                    posts: 0
                }
            },
            {
                $sort: { createdAt: -1 }
            }
        ]);
        
        console.log(`✅ Users loaded: ${users.length} users`);
        
        res.status(200).json({
            users: users,
            count: users.length
        });
        
    } catch (error) {
        console.error('❌ Users list error:', error);
        res.status(500).json({ message: 'Kullanıcılar yüklenirken hata oluştu: ' + error.message });
    }
});

// Admin: Update user (admin only)
app.put('/api/admin/users/:userId', async (req, res) => {
    try {
        console.log('👤 Admin updating user:', req.params.userId);
        
        const { name, adminId } = req.body;
        const userId = req.params.userId;
        
        // Verify admin user
        const admin = await User.findById(adminId);
        if (!admin || admin.role !== 'admin') {
            return res.status(403).json({ message: 'Admin yetkisi gerekli.' });
        }
        
        // Update user
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { name: name.trim() },
            { new: true, select: '-password' }
        );
        
        if (!updatedUser) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }
        
        console.log('✅ User updated by admin:', updatedUser.name);
        res.status(200).json({ message: 'Kullanıcı başarıyla güncellendi.', user: updatedUser });
        
    } catch (error) {
        console.error('❌ Admin update user error:', error);
        res.status(500).json({ message: 'Kullanıcı güncellenirken hata oluştu: ' + error.message });
    }
});

// Admin: Toggle user role (admin only)
app.put('/api/admin/users/:userId/role', async (req, res) => {
    try {
        console.log('👑 Admin toggling user role:', req.params.userId);
        
        const { role, adminId } = req.body;
        const userId = req.params.userId;
        
        // Verify admin user
        const admin = await User.findById(adminId);
        if (!admin || admin.role !== 'admin') {
            return res.status(403).json({ message: 'Admin yetkisi gerekli.' });
        }
        
        // Update user role
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { role },
            { new: true, select: '-password' }
        );
        
        if (!updatedUser) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }
        
        console.log('✅ User role updated by admin:', updatedUser.name, 'to', role);
        res.status(200).json({ message: 'Kullanıcı rolü başarıyla güncellendi.', user: updatedUser });
        
    } catch (error) {
        console.error('❌ Admin toggle role error:', error);
        res.status(500).json({ message: 'Rol güncellenirken hata oluştu: ' + error.message });
    }
});

// Admin: Delete user (admin only)
app.delete('/api/admin/users/:userId', async (req, res) => {
    try {
        console.log('🗑️ Admin deleting user:', req.params.userId);
        
        const { adminId } = req.body;
        const userId = req.params.userId;
        
        // Verify admin user
        const admin = await User.findById(adminId);
        if (!admin || admin.role !== 'admin') {
            return res.status(403).json({ message: 'Admin yetkisi gerekli.' });
        }
        
        // Check if trying to delete own account
        if (userId === adminId) {
            return res.status(400).json({ message: 'Kendi hesabınızı silemezsiniz.' });
        }
        
        // Find user to delete
        const userToDelete = await User.findById(userId);
        if (!userToDelete) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }
        
        // Delete user's posts first
        const deletedPosts = await Post.deleteMany({ authorId: userId });
        console.log('🗑️ Deleted user posts:', deletedPosts.deletedCount);
        
        // Delete user
        await User.findByIdAndDelete(userId);
        
        console.log('✅ User deleted by admin:', userToDelete.name);
        res.status(200).json({ 
            message: 'Kullanıcı ve tüm gönderileri başarıyla silindi.',
            deletedPosts: deletedPosts.deletedCount
        });
        
    } catch (error) {
        console.error('❌ Admin delete user error:', error);
        res.status(500).json({ message: 'Kullanıcı silinirken hata oluştu: ' + error.message });
    }
});

// Debug endpoint - Clear all users (DEVELOPMENT ONLY)
app.delete('/api/debug/clear-users', async (req, res) => {
    try {
        const result = await User.deleteMany({});
        console.log('🗑️ All users cleared from database');
        res.status(200).json({ 
            message: 'Tüm kullanıcılar temizlendi', 
            deletedCount: result.deletedCount 
        });
    } catch (error) {
        console.error('Database clear hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// Debug endpoint - List all users
app.get('/api/debug/users', async (req, res) => {
    try {
        const users = await User.find({}, { password: 0 }); // Şifreyi çıkar
        res.status(200).json({ users, count: users.length });
    } catch (error) {
        console.error('Users list hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// Debug endpoint - Create admin user (DEVELOPMENT ONLY)
app.post('/api/debug/create-admin', async (req, res) => {
    try {
        const adminEmail = 'admin@dailyloop.com';
        const adminPassword = 'admin123';
        
        // Check if admin already exists
        const existingAdmin = await User.findOne({ email: adminEmail });
        if (existingAdmin) {
            return res.status(400).json({ message: 'Admin kullanıcı zaten mevcut.' });
        }
        
        // Create admin user
        const hashedPassword = hashPassword(adminPassword);
        const adminUser = new User({
            name: 'Admin User',
            firstName: 'Admin',
            lastName: 'User',
            username: 'admin',
            email: adminEmail,
            password: hashedPassword,
            role: 'admin'
        });
        
        await adminUser.save();
        
        console.log('👑 Admin user created successfully');
        res.status(201).json({ 
            message: 'Admin kullanıcı oluşturuldu',
            admin: {
                email: adminEmail,
                password: adminPassword,
                role: 'admin'
            }
        });
    } catch (error) {
        console.error('Admin creation hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// Debug endpoint - Migrate plain text passwords to hashed (DEVELOPMENT ONLY)
app.post('/api/debug/migrate-passwords', async (req, res) => {
    try {
        const users = await User.find({});
        let migrated = 0;
        
        for (const user of users) {
            // Check if password is already hashed (contains ':')
            if (!user.password.includes(':')) {
                const hashedPassword = hashPassword(user.password);
                await User.findByIdAndUpdate(user._id, { password: hashedPassword });
                migrated++;
                console.log(`🔒 Migrated password for user: ${user.username}`);
            }
        }
        
        res.status(200).json({ 
            message: `${migrated} kullanıcının şifresi hash'lendi`,
            migrated,
            total: users.length
        });
    } catch (error) {
        console.error('Password migration hatası:', error);
        res.status(500).json({ message: 'Sunucu hatası: ' + error.message });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Endpoint bulunamadı.' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Sunucu hatası oluştu.' });
});

// Sunucuyu Başlatma
app.listen(port, () => {
    console.log(`🚀 DailyLoop Backend sunucusu http://localhost:${port} adresinde çalışıyor.`);
    console.log(`📊 Health check: http://localhost:${port}/health`);
    console.log(`📝 API endpoints: http://localhost:${port}/api/`);
});