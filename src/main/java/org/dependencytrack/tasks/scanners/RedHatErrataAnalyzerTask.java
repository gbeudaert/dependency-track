package org.dependencytrack.tasks.scanners;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.collections4.CollectionUtils;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.common.UnirestFactory;
import org.dependencytrack.event.RedHatErrataAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.ossindex.OssIndexParser;
import org.dependencytrack.parser.ossindex.model.ComponentReport;
import org.json.JSONObject;

import com.github.packageurl.PackageURL;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.logging.Logger;
import alpine.util.Pageable;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import kong.unirest.UnirestInstance;

public class RedHatErrataAnalyzerTask extends BaseComponentAnalyzerTask implements Subscriber {

	private static final String API_BASE_URL = "https://access.redhat.com/hydra/rest/securitydata";
	private static final Logger LOGGER = Logger.getLogger(RedHatErrataAnalyzerTask.class);

	private List<String> getErrataOfComponents(final List<String> componentsName) {

		return null;
	}

	/**
     * Submits the payload to the Sonatype OSS Index service
     */
    private List<ComponentReport> submit(final List<String> componentsName) throws UnirestException {
    	final List<String> erratas = getErrataOfComponents(componentsName);

    	final Map<String, String> headers = new HashMap<>();
    	headers.put("accept", "application/json");
    	headers.put("HttpHeaders.CONTENT_TYPE", "application/json");
    	headers.put("HttpHeaders.USER_AGENT", ManagedHttpClientFactory.getUserAgent());

    	final Map<String, Object> fields = new HashMap<>();
    	fields.put("advisory", erratas.stream()
    			.map(n -> String.valueOf(n))
    		    .collect(Collectors.joining(",")));

    	final UnirestInstance ui = UnirestFactory.getUnirestInstance();
    	final HttpResponse<JsonNode> jsonResponse = 
    			ui.get(API_BASE_URL  + "/cve.json")
    			.headers(headers)
    			.queryString("advisory", erratas)
    			.asJson();
    			
        if (jsonResponse.getStatus() == 200) {
            final OssIndexParser parser = new OssIndexParser();
            return parser.parse(jsonResponse.getBody());
        } else {
            LOGGER.warn("Received unexpected HTTP response " + jsonResponse.getStatus() + " " + jsonResponse.getStatusText());
        }
        return new ArrayList<>();
    }

    private static String getPackageInfoFromPurl(final PackageURL purl) {
    	return purl.getName() + "-" + purl.getVersion() + "-" + purl.getQualifiers();
    }
    
    
	@Override
	public void analyze(List<Component> components) {
		final Pageable<Component> paginatedComponents = new Pageable<>(100, components);
		while (!paginatedComponents.isPaginationComplete()) {
			final List<String> coordinates = new ArrayList<>();
			final List<Component> paginatedList = paginatedComponents.getPaginatedList();
			for (final Component component : paginatedList) {
				if (!component.isInternal() && shouldAnalyze(component.getPurl())) {
					// coordinates.add(component.getPurl().canonicalize()); // todo: put this back
					// when minimizePurl() is removed
					coordinates.add(getPackageInfoFromPurl(component.getPurl()));
				}
			}
			if (CollectionUtils.isEmpty(coordinates)) {
				return;
			}
			try {
				final List<ComponentReport> report = submit(coordinates);
				processResults(report, paginatedList);
			} catch (UnirestException e) {
				LOGGER.error("An error occurred while analyzing", e);
			}
			LOGGER.info("Analyzing " + coordinates.size() + " component(s)");
			doThrottleDelay();
			paginatedComponents.nextPage();
		}

	}

	private void processResults(List<ComponentReport> report, List<Component> paginatedList) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean shouldAnalyze(PackageURL purl) {
		return purl != null && "rpm".equalsIgnoreCase(purl.getType())
				&& !isCacheCurrent(Vulnerability.Source.RPM_ERRATA, API_BASE_URL, purl.toString());
	}

	@Override
	public void inform(Event e) {
		if (e instanceof RedHatErrataAnalysisEvent) {
			if (!super.isEnabled(ConfigPropertyConstants.SCANNER_RPMAUDIT_ENABLED)) {
				return;
			}
			final RedHatErrataAnalysisEvent event = (RedHatErrataAnalysisEvent) e;
			LOGGER.info("Starting RPM Audit analysis task");
			if (event.getComponents().size() > 0) {
				analyze(event.getComponents());
			} else {
				super.analyze();
			}
			LOGGER.info("RPM Audit analysis complete");
		}

	}

}
