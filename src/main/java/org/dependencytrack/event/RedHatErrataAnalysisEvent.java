package org.dependencytrack.event;

import java.util.List;

import org.dependencytrack.model.Component;

public class RedHatErrataAnalysisEvent extends VulnerabilityAnalysisEvent {

    public RedHatErrataAnalysisEvent() { }

    public RedHatErrataAnalysisEvent(final Component component) {
        super(component);
    }

    public RedHatErrataAnalysisEvent(final List<Component> components) {
        super(components);
    }
}
