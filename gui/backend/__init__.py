"""Backend data layer for the MOBIGUARD demo GUI.

Phase 0 modules (stdlib only -- no pandas/numpy/scipy):

``schema``     column layout of the per-cycle metrics CSV, keyed by attack id
``parser``     schema-aware decoder for those CSVs
``catalog``    filesystem index of the runs in ``results_routing/``
``aggregate``  sweep curves, 95% CI, and confusion-matrix recomputation
"""
