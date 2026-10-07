import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  SafeAreaView,
  TextInput
} from 'react-native';
import { COLORS } from '../../constants/colors';
import { useIncidents } from '../../hooks/useIncidents';
import { IncidentCard } from '../../components/IncidentCard';

const RISK_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'];

export function IncidentListScreen({ navigation }) {
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const { incidents, total, refreshing, refetch } = useIncidents({
    risk_level: activeFilter === 'ALL' ? undefined : activeFilter.toLowerCase()
  });

  const filteredIncidents = incidents.filter((item) => {
    if (!searchQuery.trim()) return true;
    const query = searchQuery.toLowerCase();
    const threatMatch = (item.threat_type || '').toLowerCase().includes(query);
    const explanationMatch = (item.explanation || '').toLowerCase().includes(query);
    return threatMatch || explanationMatch;
  });

  return (
    <SafeAreaView style={styles.safeArea}>
      {/* Top Header */}
      <View style={styles.header}>
        <TouchableOpacity
          style={styles.backBtn}
          onPress={() => navigation.goBack()}
        >
          <Text style={styles.backBtnText}>← Dashboard</Text>
        </TouchableOpacity>
        <Text style={styles.title}>Incident Triage</Text>
        <Text style={styles.subtitle}>
          {total} incidents recorded ({filteredIncidents.length} matching)
        </Text>
      </View>

      {/* Search Input */}
      <View style={styles.searchContainer}>
        <TextInput
          style={styles.searchInput}
          placeholder="Search by threat type or explanation..."
          placeholderTextColor={COLORS.textMuted}
          value={searchQuery}
          onChangeText={setSearchQuery}
        />
      </View>

      {/* Risk Filter Pills */}
      <View style={styles.filterContainer}>
        <FlatList
          horizontal
          showsHorizontalScrollIndicator={false}
          data={RISK_FILTERS}
          keyExtractor={(item) => item}
          contentContainerStyle={styles.filterList}
          renderItem={({ item }) => {
            const isActive = activeFilter === item;
            return (
              <TouchableOpacity
                style={[styles.filterChip, isActive && styles.filterChipActive]}
                onPress={() => setActiveFilter(item)}
              >
                <Text
                  style={[
                    styles.filterChipText,
                    isActive && styles.filterChipTextActive
                  ]}
                >
                  {item}
                </Text>
              </TouchableOpacity>
            );
          }}
        />
      </View>

      {/* Incident Stream */}
      <FlatList
        data={filteredIncidents}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.listContent}
        refreshing={refreshing}
        onRefresh={refetch}
        renderItem={({ item }) => (
          <IncidentCard
            incident={item}
            onPress={() => navigation.navigate('IncidentDetail', { id: item.id })}
          />
        )}
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyIcon}>🔍</Text>
            <Text style={styles.emptyTitle}>No matching incidents found</Text>
            <Text style={styles.emptySubtitle}>
              Try adjusting your filter or search query.
            </Text>
          </View>
        }
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background
  },
  header: {
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border
  },
  backBtn: {
    marginBottom: 6
  },
  backBtnText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 22,
    fontWeight: '800'
  },
  subtitle: {
    color: COLORS.textMuted,
    fontSize: 12,
    marginTop: 2
  },
  searchContainer: {
    paddingHorizontal: 16,
    paddingTop: 12,
    paddingBottom: 8
  },
  searchInput: {
    backgroundColor: COLORS.card,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 8,
    paddingHorizontal: 14,
    paddingVertical: 10,
    color: COLORS.textPrimary,
    fontSize: 13
  },
  filterContainer: {
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
    paddingBottom: 10
  },
  filterList: {
    paddingHorizontal: 16,
    gap: 8
  },
  filterChip: {
    backgroundColor: COLORS.card,
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  filterChipActive: {
    backgroundColor: COLORS.primaryMuted,
    borderColor: COLORS.primary
  },
  filterChipText: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '700'
  },
  filterChipTextActive: {
    color: COLORS.primary
  },
  listContent: {
    padding: 16,
    paddingBottom: 32
  },
  emptyContainer: {
    padding: 40,
    alignItems: 'center',
    justifyContent: 'center'
  },
  emptyIcon: {
    fontSize: 32,
    marginBottom: 10
  },
  emptyTitle: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '700',
    marginBottom: 4
  },
  emptySubtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    textAlign: 'center'
  }
});
