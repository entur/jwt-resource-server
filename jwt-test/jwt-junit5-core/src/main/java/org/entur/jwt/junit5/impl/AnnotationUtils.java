package org.entur.jwt.junit5.impl;

import java.lang.annotation.Annotation;
import java.lang.annotation.Inherited;
import java.lang.reflect.AnnotatedElement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A few utilities which are not exposed to external modules.
 * 
 * @see org.junit.platform.commons.support.AnnotationSupport#findAnnotation(AnnotatedElement,
 *      Class)
 */

public class AnnotationUtils {

    private AnnotationUtils() {
        // utility class
    }

    public static <A extends Annotation> Optional<A> findAnnotation(AnnotatedElement element, Class<A> annotationType) {
        boolean inherited = annotationType.isAnnotationPresent(Inherited.class);
        return findAnnotation(element, annotationType, inherited, new HashSet<>());
    }

    private static <A extends Annotation> Optional<A> findAnnotation(AnnotatedElement element, Class<A> annotationType, boolean inherited, Set<Annotation> visited) {

        if (element == null) {
            return Optional.empty();
        }

        // Directly present?
        A annotation = element.getDeclaredAnnotation(annotationType);
        if (annotation != null) {
            return Optional.of(annotation);
        }

        // Meta-present on directly present annotations?
        Optional<A> directMetaAnnotation = findMetaAnnotation(annotationType, element.getDeclaredAnnotations(), inherited, visited);
        if (directMetaAnnotation.isPresent()) {
            return directMetaAnnotation;
        }

        if (element instanceof Class) {
            Class<?> clazz = (Class<?>) element;

            // Search on interfaces
            for (Class<?> ifc : clazz.getInterfaces()) {
                if (ifc != Annotation.class) {
                    Optional<A> annotationOnInterface = findAnnotation(ifc, annotationType, inherited, visited);
                    if (annotationOnInterface.isPresent()) {
                        return annotationOnInterface;
                    }
                }
            }

            // Indirectly present?
            // Search in class hierarchy
            if (inherited) {
                Class<?> superclass = clazz.getSuperclass();
                if (superclass != null && superclass != Object.class) {
                    Optional<A> annotationOnSuperclass = findAnnotation(superclass, annotationType, inherited, visited);
                    if (annotationOnSuperclass.isPresent()) {
                        return annotationOnSuperclass;
                    }
                }
            }
        }

        // Meta-present on indirectly present annotations?
        return findMetaAnnotation(annotationType, element.getAnnotations(), inherited, visited);
    }

    /**
     * Find the annotation which is directly annotated with the supplied meta-annotation type, i.e. the supplied
     * annotation itself or one of its (meta-)annotations.
     *
     * @param annotation annotation to search
     * @param metaAnnotationType meta-annotation type
     * @return the annotation (not the meta-annotation), or empty if the meta-annotation is not present
     */

    public static Optional<Annotation> findMetaAnnotatedAnnotation(Annotation annotation, Class<? extends Annotation> metaAnnotationType) {
        List<Annotation> annotations = findMetaAnnotatedAnnotations(annotation, metaAnnotationType);
        return annotations.isEmpty() ? Optional.empty() : Optional.of(annotations.get(0));
    }

    /**
     * Find all annotations which carry the given meta-annotation: the annotation itself, or (recursively) its meta-annotations.
     *
     * @param annotation the annotation
     * @param metaAnnotationType the meta-annotation type
     * @return the annotations which are annotated with the meta-annotation
     */

    public static List<Annotation> findMetaAnnotatedAnnotations(Annotation annotation, Class<? extends Annotation> metaAnnotationType) {
        List<Annotation> results = new ArrayList<>();
        findMetaAnnotatedAnnotations(annotation, metaAnnotationType, new HashSet<>(), results);
        return results;
    }

    private static void findMetaAnnotatedAnnotations(Annotation annotation, Class<? extends Annotation> metaAnnotationType, Set<Annotation> visited, List<Annotation> results) {
        Class<? extends Annotation> annotationType = annotation.annotationType();
        // note: visit annotations (not annotation types), as the same annotation type might be used with different attributes
        if (isInJavaLangAnnotationPackage(annotationType) || !visited.add(annotation)) {
            return;
        }
        if (annotationType.getDeclaredAnnotation(metaAnnotationType) != null) {
            results.add(annotation);
        }
        for (Annotation candidate : annotationType.getDeclaredAnnotations()) {
            findMetaAnnotatedAnnotations(candidate, metaAnnotationType, visited, results);
        }
    }

    private static <A extends Annotation> Optional<A> findMetaAnnotation(Class<A> annotationType, Annotation[] candidates, boolean inherited, Set<Annotation> visited) {

        for (Annotation candidateAnnotation : candidates) {
            Class<? extends Annotation> candidateAnnotationType = candidateAnnotation.annotationType();
            if (!isInJavaLangAnnotationPackage(candidateAnnotationType) && visited.add(candidateAnnotation)) {
                Optional<A> metaAnnotation = findAnnotation(candidateAnnotationType, annotationType, inherited, visited);
                if (metaAnnotation.isPresent()) {
                    return metaAnnotation;
                }
            }
        }
        return Optional.empty();
    }

    private static boolean isInJavaLangAnnotationPackage(Class<? extends Annotation> annotationType) {
        return (annotationType != null && annotationType.getName().startsWith("java.lang.annotation"));
    }

}
