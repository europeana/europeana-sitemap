package eu.europeana.sitemap;

import eu.europeana.sitemap.web.context.SocksProxyConfigInjector;
import org.apache.logging.log4j.LogManager;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.context.annotation.PropertySource;


import java.io.IOException;

/**
 * Main application and configuration
 * @author Patrick Ehlert on 14-11-17.
 */
@SpringBootApplication(exclude={MongoAutoConfiguration.class})
@PropertySource("classpath:build.properties")
public class SitemapApplication {

    /**
     * This method is called when starting as a Spring-Boot application (e.g. from your IDE)
     * @param args main application arguments
     */
    @SuppressWarnings("squid:S2095") // to avoid sonarqube false positive (see https://stackoverflow.com/a/37073154/741249)
    public static void main(String[] args)  {
        LogManager.getLogger(SitemapApplication.class).info("MAIN START");
        LogManager.getLogger(SitemapApplication.class).info("CF_INSTANCE_INDEX  = {}, CF_INSTANCE_GUID = {}, CF_INSTANCE_IP  = {}",
                System.getenv("CF_INSTANCE_INDEX"), System.getenv("CF_INSTANCE_GUID"), System.getenv("CF_INSTANCE_IP"));

        try {
            injectSocksProxySettings();
            SpringApplication.run(SitemapApplication.class, args);
        } catch (IOException e) {
            LogManager.getLogger(SitemapApplication.class).fatal("Error reading properties", e);
            System.exit(-1);
        }
    }

    @SuppressWarnings("squid:S1166") // we intentionally do not log exception stacktrace here
    private static void injectSocksProxySettings() throws IOException {
        SocksProxyConfigInjector socksConfig = new SocksProxyConfigInjector("sitemap.properties");
        try {
            socksConfig.addProperties("sitemap.user.properties");
        } catch (IOException e) {
            // user.properties may not be available so only show warning
            LogManager.getLogger(SitemapApplication.class).warn("Cannot read sitemap.user.properties file");
        }
        socksConfig.inject();
    }
    
}
