import React from 'react';
import { useState } from 'react';
import { Text, TouchableOpacity, View, SafeAreaView, ScrollView, StyleSheet } from 'react-native';

import ZeroxTSS from 'rn-tss-module/js/NativeTss';

const getSession = (party_index: number) => ({
    // using hardcoded session_id and parameters in order to reproduce DKLs23
    // deterministic results (if wanted)
    parameters: { threshold: 2, share_count: 2 },
    session_id: [155, 91, 34, 177, 234, 249, 164, 92, 254, 10, 140, 65, 30,
        135, 113, 112, 137, 57, 36, 209, 201, 197, 182, 252, 49, 111, 29, 209,
        53, 68, 140, 219
    ],
    party_index,
})

const dkgPhase1 = async (parties: []) => await Promise.all(
    parties.map(async session => {
        const { fragments } = JSON.parse(
            await ZeroxTSS?.DKLsDkgPhase1(JSON.stringify({ session }))
        );

        return { fragments };
    })
);

const DKLsDKG = async (setDKGStatus: Function) => {
    const parties = [getSession(1), getSession(2)];
    const phase1Out = await dkgPhase1(parties);
    setDKGStatus(JSON.stringify({
        'party 1': phase1Out[0],
        'party 2': phase1Out[1],
    }, null, 2));
}

function App(): React.JSX.Element {
    const [DKGStatus, setDKGStatus] = useState("DKG hasn't started yet.");
    return (
        <SafeAreaView>
          <ScrollView contentContainerStyle={styles.container}>
            <View style={styles.titleContainer}>
              <Text style={styles.title}>DKLs23 - DKG phase 1 example</Text>
            </View>
            <View style={styles.statusContainer}>
              <Text>{DKGStatus}</Text>
            </View>
            <View style={styles.buttonContainer}>
              <TouchableOpacity
                style={styles.button}
                onPress={() => DKLsDKG(setDKGStatus)}
              >
                <Text style={styles.buttonText}>Test DKG phase 1</Text>
              </TouchableOpacity>
            </View>
          </ScrollView>
        </SafeAreaView>
    );
}

const styles = StyleSheet.create({
    container: {
        flexGrow: 1,
        justifyContent: 'center',
        alignItems: 'center',
        padding: 16,
    },
    titleContainer: {
        marginBottom: 20,
    },
    title: {
        fontSize: 24,
        fontWeight: 'bold',
        textAlign: 'center',
    },
    statusContainer: {
        marginBottom: 20,
    },
    buttonContainer: {
        marginTop: 20,
    },
    button: {
        backgroundColor: '#007BFF',
        paddingVertical: 10,
        paddingHorizontal: 20,
        borderRadius: 5,
    },
    buttonText: {
        color: '#FFFFFF',
        fontSize: 16,
    },
});

export default App;
