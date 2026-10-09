import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity
} from 'react-native';
import { useTheme } from '../../context/ThemeContext';
import { useIncidents } from '../../hooks/useIncidents';
import { AppHeader } from '../../components/AppHeader';
import { BottomTabBar } from '../../components/BottomTabBar';
import { Card } from '../../components/Card';
import { Badge } from '../../components/Badge';

const STATUS_FILTERS = ['All', 'Open', 'Resolved'];
const THREAT_FILTERS = ['All', 'Phishing', 'Malware', 'Deepfake', 'Credential', 'Scam'];
const TIME_FILTERS = ['Today', 'Last 7 days', 'Last 30 days'];

export function IncidentListScreen({ navigation }) {
  const { colors } = useTheme();
  const [statusFilter, setStatusFilter] = useState('All');
  const [threatFilter, setThreatFilter] = useState('All');
  const [timeFilter, setTimeFilter] = useState('Last 7 days');

  const { incidents, total, refreshing, refetch } = useIncidents();

  // Multi-tier filtering
  const filteredIncidents = incidents.filter((item) => {
    // Status filter
    if (statusFilter === 'Open') {
      if (item.status && item.status !== 'open' && item.status !== 'investigating') return false;
    } else if (statusFilter === 'Resolved') {
      if (item.status !== 'resolved') return false;
    }

    // Threat type filter
    if (threatFilter !== 'All') {
      const type = (item.threat_type || '').toLowerCase();
      if (!type.includes(threatFilter.toLowerCase())) return false;
    }

    // Time filter
    if (item.created_at) {
      const createdDate = new Date(item.created_at).getTime();
      const now = Date.now();
      const diffHours = (now - createdDate) / (1000 * 60 * 60);

      if (timeFilter === 'Today' && diffHours > 24) return false;
      if (timeFilter === 'Last 7 days' && diffHours > 24 * 7) return false;
      if (timeFilter === 'Last 30 days' && diffHours > 24 * 30) return false;
    }

    return true;
  });

  const formatTimeAgo = (dateStr) => {
    if (!dateStr) return 'Recent';
    const diffMin = Math.round((Date.now() - new Date(dateStr).getTime()) / 60000);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.round(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.round(diffHours / 24)}d ago`;
  };

  return (
    <View style={[styles.safeArea, { backgroundColor: colors.background }]}>
      <AppHeader title="Activity / Incidents" navigation={navigation} />

      {/* Filter Bar */}
      <View style={[styles.filtersContainer, { backgroundColor: colors.card, borderBottomColor: colors.border }]}>
        {/* Status Filter */}
        <View style={styles.filterRow}>
          <Text style={[styles.filterGroupLabel, { color: colors.textMuted }]}>STATUS:</Text>
          <View style={styles.chipRow}>
            {STATUS_FILTERS.map((s) => (
              <TouchableOpacity
                key={s}
                style={[
                  styles.filterChip,
                  statusFilter === s
                    ? { backgroundColor: colors.accent, borderColor: colors.accent }
                    : { backgroundColor: 'transparent', borderColor: colors.border }
                ]}
                onPress={() => setStatusFilter(s)}
              >
                <Text
                  style={[
                    styles.filterChipText,
                    { color: statusFilter === s ? '#000000' : colors.textSecondary }
                  ]}
                >
                  {s}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>

        {/* Threat Type Filter */}
        <View style={styles.filterRow}>
          <Text style={[styles.filterGroupLabel, { color: colors.textMuted }]}>TYPE:</Text>
          <FlatList
            horizontal
            showsHorizontalScrollIndicator={false}
            data={THREAT_FILTERS}
            keyExtractor={(i) => i}
            contentContainerStyle={styles.chipScroll}
            renderItem={({ item }) => (
              <TouchableOpacity
                style={[
                  styles.filterChip,
                  threatFilter === item
                    ? { backgroundColor: colors.accent, borderColor: colors.accent }
                    : { backgroundColor: 'transparent', borderColor: colors.border }
                ]}
                onPress={() => setThreatFilter(item)}
              >
                <Text
                  style={[
                    styles.filterChipText,
                    { color: threatFilter === item ? '#000000' : colors.textSecondary }
                  ]}
                >
                  {item}
                </Text>
              </TouchableOpacity>
            )}
          />
        </View>

        {/* Time Filter */}
        <View style={styles.filterRow}>
          <Text style={[styles.filterGroupLabel, { color: colors.textMuted }]}>TIME:</Text>
          <View style={styles.chipRow}>
            {TIME_FILTERS.map((t) => (
              <TouchableOpacity
                key={t}
                style={[
                  styles.filterChip,
                  timeFilter === t
                    ? { backgroundColor: colors.surface, borderColor: colors.accent }
                    : { backgroundColor: 'transparent', borderColor: colors.border }
                ]}
                onPress={() => setTimeFilter(t)}
              >
                <Text
                  style={[
                    styles.filterChipText,
                    { color: timeFilter === t ? colors.accent : colors.textMuted }
                  ]}
                >
                  {t}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>
      </View>

      {/* Incident List */}
      <FlatList
        data={filteredIncidents}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.listContent}
        refreshing={refreshing}
        onRefresh={refetch}
        ListHeaderComponent={
          <View style={styles.listHeader}>
            <Text style={[styles.resultsCount, { color: colors.textSecondary }]}>
              {filteredIncidents.length} incidents logged
            </Text>
          </View>
        }
        ListEmptyComponent={
          <Card style={styles.emptyCard}>
            <Text style={[styles.emptyText, { color: colors.textMuted }]}>
              No matching incidents found for the active filter set.
            </Text>
          </Card>
        }
        renderItem={({ item }) => {
          const statusText = (item.status || 'open').toUpperCase();
          const threatTitle = item.title || `${item.threat_type ? item.threat_type.toUpperCase() : 'SECURITY'} - ${item.target_summary || 'Anomalous event'}`;
          const timeAgo = formatTimeAgo(item.created_at);

          return (
            <Card
              style={styles.incidentCard}
              onPress={() => navigation.navigate('IncidentDetail', { id: item.id })}
            >
              <View style={styles.cardTopRow}>
                <Text
                  style={[styles.cardTitle, { color: colors.textPrimary }]}
                  numberOfLines={1}
                >
                  {threatTitle}
                </Text>
                <Badge level={item.risk_level} text={item.risk_level} />
              </View>

              <Text
                style={[styles.cardDesc, { color: colors.textBody }]}
                numberOfLines={2}
              >
                {item.description || item.explanation || 'Heuristic inspection flagged urgent indicators.'}
              </Text>

              <View style={[styles.cardFooter, { borderTopColor: colors.border }]}>
                <Text style={[styles.timeText, { color: colors.textMuted }]}>
                  {timeAgo}
                </Text>
                <Badge
                  text={statusText}
                  status={item.status === 'resolved' ? 'resolved' : 'pending'}
                />
              </View>
            </Card>
          );
        }}
      />

      <BottomTabBar activeRoute="IncidentList" navigation={navigation} />
    </View>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1
  },
  filtersContainer: {
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderBottomWidth: 1,
    gap: 8
  },
  filterRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8
  },
  filterGroupLabel: {
    fontSize: 10,
    fontWeight: '800',
    width: 52,
    letterSpacing: 0.6
  },
  chipRow: {
    flexDirection: 'row',
    gap: 6
  },
  chipScroll: {
    flexDirection: 'row',
    gap: 6
  },
  filterChip: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 4,
    borderWidth: 1
  },
  filterChipText: {
    fontSize: 11,
    fontWeight: '700'
  },
  listContent: {
    padding: 16,
    paddingBottom: 24
  },
  listHeader: {
    marginBottom: 10
  },
  resultsCount: {
    fontSize: 12,
    fontWeight: '600'
  },
  incidentCard: {
    marginBottom: 8
  },
  cardTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 6,
    gap: 8
  },
  cardTitle: {
    fontSize: 14,
    fontWeight: '700',
    flex: 1
  },
  cardDesc: {
    fontSize: 12,
    lineHeight: 17,
    marginBottom: 10
  },
  cardFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    borderTopWidth: 1,
    paddingTop: 8
  },
  timeText: {
    fontSize: 11,
    fontWeight: '500'
  },
  emptyCard: {
    paddingVertical: 32,
    alignItems: 'center'
  },
  emptyText: {
    fontSize: 13
  }
});
