package eu.europeana.sitemap.service.update;

import eu.europeana.sitemap.SitemapType;
import eu.europeana.sitemap.exceptions.SiteMapException;

/**
 * Update interface for classes that support updating a particular sitemap type
 * @author Patrick Ehlert
 * Created on 14-06-2018
 */
public interface UpdateService {

    /**
     * Triggers a sitemap update
     * @throws SiteMapException when there is an error during the update process
     */
    public void update() throws SiteMapException;

    /**
     * @return the type of the sitemap that should be updated
     */
    public SitemapType getSitemapType();

    /**
     * @return cron style interval for when automatic updates should be done, can be left empty
     */
    public String getUpdateInterval();

    /**
     * Method that allows implementing services to indicate whether a changed sitemap index files should be
     * resubmitted to search engines or not
     * @return true if it should be resubmitting, otherwise false
     */
    public boolean doResubmit();

}
