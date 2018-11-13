Creates and publishes a record and entity sitemaps
 
The record sitemap is generated by connecting to a Mongo server and listing all records
The entity sitemap uses entity-APIs search functionality to retrieve all entities.
 
For both, the generated sitemap consists of:
 - multiple sitemap files containing record urls (45.000 per file)
 - a sitemap index file listing all the sitemap files
  
To make sure there is always a sitemap available, we use blue/green versions of the sitemap files. At the start of the
update process any old blue/green version left is deleted before the new sitemap files are created.

For more information about sitemaps in general see also https://support.google.com/webmasters/answer/183668?hl=en

**Run**

You can either run the application directly in your IDE (select 'Run' on SitemapApplication class) or
you can run `mvn clean package` and then start the provided docker-compose file (run `docker-compose up` in the 
application root folder)

For debugging purposes you can use the following urls:

  - `/sitemap/files` shows a list of stored files
  - `/sitemap/file?name=x` shows the contents of the stored file with the name x
  
  - `/sitemap/record/index` and `sitemap/entity/index` shows the contents of the sitemap index files  

Note that you can only run `/sitemap/record/update` or `/sitemap/entity/update` manually if you configure and provide an
administrator apikey e.g. `/sitemap/record/update?wskey=<enter_adminkey_here>`