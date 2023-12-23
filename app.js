if (process.env.NODE_ENV !== "production") {
    require('dotenv').config();
}

const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const ejsMate = require('ejs-mate');
const session = require('express-session');
const flash = require('connect-flash');
const Sentiment = require("sentiment");
const ExpressError = require('./utils/ExpressError');
const methodOverride = require('method-override');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const User = require('./models/user');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const userRoutes = require('./routes/users');
const campgroundRoutes = require('./routes/campgrounds');
const reviewRoutes = require('./routes/reviews');
const catchAsync = require('./utils/catchAsync');
const MongoDBStore = require("connect-mongo")(session);
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const { uploadFile, getFileStream } = require("./s3");
const Campground = require('./models/campground')

const dbUrl = process.env.DB_URL || 'mongodb://localhost:27017/yelp-camp';

mongoose.connect(dbUrl, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
    useFindAndModify: false
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
    console.log("Database connected");
});

const app = express();

app.engine('ejs', ejsMate)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'))

app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')))
app.use(mongoSanitize({
    replaceWith: '_'
}))
const secret = process.env.SECRET || 'thisshouldbeabettersecret!';

const store = new MongoDBStore({
    url: dbUrl,
    secret,
    touchAfter: 24 * 60 * 60
});

store.on("error", function (e) {
    console.log("SESSION STORE ERROR", e)
})

const sessionConfig = {
    store,
    name: 'session',
    secret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        // secure: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}

app.use(session(sessionConfig));
app.use(flash());
app.use(helmet());


const scriptSrcUrls = [
    "https://stackpath.bootstrapcdn.com",
    "https://api.tiles.mapbox.com",
    "https://api.mapbox.com",
    "https://kit.fontawesome.com",
    "https://cdnjs.cloudflare.com",
    "https://cdn.jsdelivr.net",
];
const styleSrcUrls = [
    "https://kit-free.fontawesome.com",
    "https://stackpath.bootstrapcdn.com",
    "https://api.mapbox.com",
    "https://api.tiles.mapbox.com",
    "https://fonts.googleapis.com",
    "https://use.fontawesome.com",
];
const connectSrcUrls = [
    "https://api.mapbox.com",
    "https://*.tiles.mapbox.com",
    "https://quickchart.io",
    "https://events.mapbox.com",
];
const fontSrcUrls = [];
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: [],
            connectSrc: ["'self'", ...connectSrcUrls],
            scriptSrc: ["'unsafe-inline'", "'self'", ...scriptSrcUrls],
            styleSrc: ["'self'", "'unsafe-inline'", ...styleSrcUrls],
            workerSrc: ["'self'", "blob:"],
            childSrc: ["blob:"],
            objectSrc: [],
            imgSrc: [
                "'self'",
                "blob:",
                "data:",
                "https://res.cloudinary.com/douqbebwk/", //SHOULD MATCH YOUR CLOUDINARY ACCOUNT! 
                "https://images.unsplash.com",
                "https://quickchart.io",
            ],
            fontSrc: ["'self'", ...fontSrcUrls],
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

const fetchRating = async (theUser) => {
    const userCampgrounds = await Campground.find({
      author: theUser._id,
    }).populate("reviews");
    let totalRating = 0;
    let totalReviews = 0;
  
    userCampgrounds.forEach((campground) => {
      campground.reviews.forEach((review) => {
        totalRating += review.rating;
        totalReviews++;
      });
    });
    const averageRating = totalReviews > 0 ? totalRating / totalReviews : 0;
    return averageRating;
  };

app.use(async(req, res, next) => {
    res.locals.currentUser = req.user;
    if (req.user) {
        res.locals.userRating = await fetchRating(req.user);
      } else {
        res.locals.userRating = 0;
      }
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
})

app.post('/register',upload.single("image"),catchAsync(async(req,res)=>{
    const { email, username, password } = await req.body;
    console.log("req.body adani: ", req.body);

    const file = req.file;
    const uploadedFile = await uploadFile(file);
    console.log(uploadFile)

    const user = await new User({
      email,
      username,
      profilePic: uploadedFile.Key,
    });
    console.log(user);
    console.log(uploadedFile);

    const registeredUser = await User.register(user, password);
    req.login(registeredUser, (err) => {
      if (err) console.log(err);
      console.log("req.user: ", req.user);
      req.flash("success", "Welcome to Medi Camp!");
      res.redirect("/campgrounds");
    });
}))
app.use('/', userRoutes);
app.use('/campgrounds', campgroundRoutes)
app.use('/campgrounds/:id/reviews', reviewRoutes)


app.get('/', (req, res) => {
    res.render('home')
});

app.get('/better',(req,res)=>{
    res.render('campgrounds/better2.ejs')
})

app.get("/images/:key", (req, res) => {
    console.log("hello");
    const key = req.params.key;
    const readStream = getFileStream(key);
  
    readStream.pipe(res);
  });

function SentimentArray(array) {
    const sentiment = new Sentiment();
    let pos = 0;
    let neg = 0;
  
    array.forEach((review) => {
      if (typeof review === "string") {
        const reviewSentiment = sentiment.analyze(review);
        if (reviewSentiment.score > 0) {
          pos++;
        } else if (reviewSentiment.score < 0) {
          neg++;
        }
      }
    });
  
    // Create an object in the required format
    const chartData = {
      type: "pie",
      data: {
        labels: ["Positive", "Negative"],
        datasets: [
          {
            data: [pos, neg],
          },
        ],
      },
    };
  
    // Convert the object to a JSON string and encode it for the URL
    const chartDataEncoded = encodeURIComponent(JSON.stringify(chartData));
  
    const chartUrl = `https://quickchart.io/chart?c=${chartDataEncoded}`;
  
    return chartUrl;
  }
  
  app.get("/profile", async (req, res) => {
    try {
      const userCampgrounds = await Campground.find({
        author: req.user._id,
      }).populate("reviews");
      const everyRating = [0, 0, 0, 0, 0];
  
      let totalRating = 0;
      let totalReviews = 0;
      const reviewsAll = [];
  
      userCampgrounds.forEach((campground) => {
        campground.reviews.forEach((review) => {
          reviewsAll.push(review.body);
          everyRating[review.rating - 1]++;
          totalRating += review.rating;
          totalReviews++;
        });
      });
      const reviewsAllSentiment = SentimentArray(reviewsAll);
  
      const averageRating = totalReviews > 0 ? totalRating / totalReviews : 0;
  
      const sessionDurationMinutes =
        Math.floor(req.session.cookie._expires / 60000) || 0;
      const expirationTime = new Date(
        Date.now() + req.session.cookie.originalMaxAge
      );
  
      const everyRatingString = JSON.stringify(everyRating);
  
      const chartURLFunc = async () => {
        return await [
          `https://quickchart.io/chart?c={type:'bar',data:{labels:['1','2','3','4','5'], datasets:[{label:'Reviews',data: ${everyRatingString}}]}}`,
          SentimentArray(reviewsAll),
        ];
      };
      const chartURL = await chartURLFunc();
      res.render("users/profile", {
        sessionDurationMinutes,
        expirationTime,
        averageRating,
        everyRating,
        chartURL,
      });
    } catch (err) {
      console.error(err);
      res.redirect("/");
    }
  });


app.all('*', (req, res, next) => {
    next(new ExpressError('Page Not Found', 404))
})

app.use((err, req, res, next) => {
    const { statusCode = 500 } = err;
    if (!err.message) err.message = 'Oh No, Something Went Wrong!'
    res.status(statusCode).render('error', { err })
})

const port = process.env.PORT || 8000;
app.listen(port, () => {
    console.log(`Serving on port ${port}`)
})
