package eu.europeana.sitemap.web;

import eu.europeana.sitemap.exceptions.SiteMapNotFoundException;
import eu.europeana.sitemap.service.ReadSitemapService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Generic functionality for reading sitemap files (for testing and debugging)
 *
 * @author Patrick Ehlert
 * Created on 30-05-2018
 */
@RestController
@RequestMapping(value = "/", produces = {MediaType.TEXT_PLAIN_VALUE, MediaType.TEXT_XML_VALUE, MediaType.APPLICATION_XML_VALUE})
public class SitemapFileController {

    private static final Logger LOG = LogManager.getLogger(SitemapFileController.class);

    protected final ReadSitemapService service;

    @Autowired
    public SitemapFileController(ReadSitemapService service) {
        this.service = service;
    }

    /**
     * Lists all files stored in the used bucket (for debugging purposes)
     * @return list of all files in the bucket
     */
    @GetMapping(value = {"list", "files"})
    public String files() {
        return service.getFiles();
    }

    /**
     * Returns the contents of a particular file
     * @param fileName name of the requested file
     * @return contents of the requested file
     */
    @GetMapping("file")
    public String file(@RequestParam(value = "name", defaultValue = "") String fileName) throws SiteMapNotFoundException {
        LOG.debug("Retrieving file {} ", fileName);
        if (fileName == null || fileName.isEmpty()) {
            throw new IllegalArgumentException("Please provide a file name");
        }
        return service.getFileContent(fileName);
    }
}
