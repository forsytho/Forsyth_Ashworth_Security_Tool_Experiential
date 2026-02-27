package com.dynamicduo.proto.analyzer;

import com.dynamicduo.proto.ast.*;
import java.util.*;

public record KnowledgeResult(
        Map<String, Set<String>> knows,                 // atoms learned (ids, keys, nonces, etc.)
        Map<String, Set<KnowledgeAnalyzer.EncTerm>> encryptTerms,  // opaque enc terms
        Map<String, KeyKind> keyKinds,
        Set<String> secretKeys,
        Set<String> cryptoVars,
        List<KnowledgeAnalyzer.FreshnessResult> freshnessResults,
        Map<String, Map<String, String>> trustedPublicKeyBindings
) {}
