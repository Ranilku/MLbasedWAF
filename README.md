This is an Machine learning based Web Application Firewall. Using Python a diversified dataset with both good and bad queries was used to extract multiple features from the queries in the dataset.
There were in total 25 features that were extracted and multiple ML Algorithms were run against the dataset. XGBoost, SVM and RandomForest all performed well. However XGBoost was much quicker, SVM was the most slowest. XGBoost was then used to carryout a Feature Importance analysis on the dataset and based on top 16 features contributing to Algorithm's ability in distinguishing normal or malicious traffic, a Model was built.

Flask was used to build 2 applications.
WAF : Which uses the XGBoost model to evaluate incoming request and either block or allow traffic to pass to Webserver.

Backed: This is a webserver.

When setup, WAF would receive incoming traffic and pass it to backend webserver based on model's evaluation.
